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
module: intersight_vlan_policy
short_description: Manage VLAN Policies and VLANs for Cisco Intersight
description:
  - Create, update, and delete VLAN Policies on Cisco Intersight.
  - Manage individual VLANs within VLAN policies.
  - Supports both regular VLANs and Private VLANs (Primary, Isolated, Community) configurations.
  - VLAN policies define network segmentation and can be attached to LAN Connectivity policies and Server Profiles.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/fabric/EthNetworkPolicy/get/).
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
      - The name assigned to the VLAN Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the VLAN Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  vlans:
    description:
      - List of VLANs to be created and attached to the VLAN policy.
      - Each VLAN will be named as C(prefix_vlan_id) (e.g., prod_100).
      - Leave empty to create a policy without VLANs for manual configuration later.
    type: list
    elements: dict
    suboptions:
      prefix:
        description:
          - Prefix for the VLAN name.
          - Combined with vlan_id to create the full VLAN name (prefix_vlan_id).
        type: str
        required: true
      vlan_id:
        description:
          - Enter a valid VLAN ID or ID range between 2 and 4093.
          - You can enter a range of IDs using a hyphen (e.g., "30-40" will create VLANs 30 through 40).
          - Examples of valid VLAN IDs or ID ranges are 50, 200, "2000-2100".
          - You cannot use VLANs from 4043-4047, 4094, and 4095 because these IDs are reserved for system use.
          - You can create a maximum of 3000 VLANs at a time.
          - VLAN ID - single ID 100 or range "30-40" (ranges require quotes).
          - Must be unique within the fabric interconnect domain.
          - When using ranges, multiple VLANs will be created with names following the pattern prefix_vlanid.
          - For non-contiguous VLANs, create separate VLAN blocks rather than using comma-separated values.
        type: str
        required: true
      is_native:
        description:
          - Whether this VLAN is the native VLAN for the fabric interconnect domain.
        type: bool
        default: false
      auto_allow_on_uplinks:
        description:
          - Whether to automatically allow this VLAN on uplinks.
        type: bool
        default: true
      enable_sharing:
        description:
          - When selected, enables Private VLAN sharing options.
        type: bool
        default: false
      multicast_policy_name:
        description:
          - Name of the multicast policy to associate with this VLAN.
          - Required when enable_sharing is false.
        type: str
      sharing_type:
        description:
          - Type of VLAN sharing when enable_sharing is true.
        type: str
        choices: ['Primary', 'Isolated', 'Community']
      primary_vlan_id:
        description:
          - The Primary VLAN ID of the VLAN, if the sharing type of the VLAN is Isolated or Community.
        type: int
      state:
        description:
          - Whether to create/update or delete the VLAN.
        type: str
        choices: ['present', 'absent']
        default: present
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a VLAN Policy with multiple VLANs
  cisco.intersight.intersight_vlan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "datacenter-vlan-policy"
    description: "VLAN policy for datacenter infrastructure"
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
    vlans:
      - prefix: "prod"
        vlan_id: 100
        auto_allow_on_uplinks: true
        enable_sharing: false
        multicast_policy_name: "default-multicast-policy"
      - prefix: "dev"
        vlan_id: 200
        auto_allow_on_uplinks: false
        enable_sharing: false
        multicast_policy_name: "default-multicast-policy"
      - prefix: "mgmt"
        vlan_id: 300
        auto_allow_on_uplinks: true
        enable_sharing: false
        multicast_policy_name: "default-multicast-policy"
        is_native: true
    state: present

- name: Create a VLAN Policy with VLAN sharing (Private VLANs)
  cisco.intersight.intersight_vlan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "private-vlan-policy"
    description: "Policy with private VLAN configuration"
    vlans:
      - prefix: "primary"
        vlan_id: 79
        enable_sharing: true
        sharing_type: "Primary"
        auto_allow_on_uplinks: true
      - prefix: "isolated"
        vlan_id: 90
        enable_sharing: true
        sharing_type: "Isolated"
        primary_vlan_id: 79
        auto_allow_on_uplinks: true
      - prefix: "community"
        vlan_id: 91
        enable_sharing: true
        sharing_type: "Community"
        primary_vlan_id: 79
        auto_allow_on_uplinks: true
    state: present

- name: Create a VLAN Policy with mixed configurations
  cisco.intersight.intersight_vlan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
    name: "mixed-vlan-policy"
    description: "Mixed configuration with shared and non-shared VLANs"
    vlans:
      - prefix: "web"
        vlan_id: 10
        auto_allow_on_uplinks: true
        enable_sharing: false
        multicast_policy_name: "web-multicast-policy"
      - prefix: "db"
        vlan_id: 20
        auto_allow_on_uplinks: false
        enable_sharing: false
        state: absent
        multicast_policy_name: "db-multicast-policy"
      - prefix: "dmz_primary"
        vlan_id: 50
        enable_sharing: true
        sharing_type: "Primary"
        auto_allow_on_uplinks: true
        state: present
      - prefix: "dmz_isolated"
        vlan_id: 51
        enable_sharing: true
        sharing_type: "Isolated"
        primary_vlan_id: 50
        auto_allow_on_uplinks: true
    state: present

- name: Create a VLAN Policy with VLAN ranges
  cisco.intersight.intersight_vlan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "range-vlan-policy"
    description: "Policy with VLAN ranges"
    vlans:
      - prefix: "prod"
        vlan_id: "30-40"
        auto_allow_on_uplinks: true
        enable_sharing: false
        multicast_policy_name: "default-multicast-policy"
      - prefix: "dev"
        vlan_id: "100-110"
        auto_allow_on_uplinks: true
        enable_sharing: false
        multicast_policy_name: "default-multicast-policy"
      - prefix: "mgmt"
        vlan_id: 200
        auto_allow_on_uplinks: true
        enable_sharing: false
        multicast_policy_name: "default-multicast-policy"
    state: present

- name: Create a VLAN Policy with minimal configuration (policy only)
  cisco.intersight.intersight_vlan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "empty-vlan-policy"
    description: "Empty policy for manual VLAN configuration"
    state: present

- name: Update an existing VLAN Policy
  cisco.intersight.intersight_vlan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vlan-policy"
    description: "Updated description for datacenter infrastructure"
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Site"
        Value: "DataCenter-A"
      - Key: "Updated"
        Value: "2024-01-01"
    state: present

- name: Delete a VLAN Policy
  cisco.intersight.intersight_vlan_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "datacenter-vlan-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test_vlan_policy",
        "ObjectType": "fabric.EthNetworkPolicy",
        "Tags": [
            {
                "Key": "Site",
                "Value": "DataCenter-A"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec, compare_values


def parse_vlan_id_range(vlan_id_input):
    """
    Parse VLAN ID input which can be:
    - String with single ID: "100"
    - String with range: "100-110"
    Args:
        vlan_id_input: VLAN ID as string
    Returns:
        List of individual VLAN IDs
    Raises:
        ValueError: If the input format is invalid
    """
    vlan_ids = []
    # Parse string input
    vlan_id_str = str(vlan_id_input).strip()
    # Check for comma-separated values and reject them
    if ',' in vlan_id_str:
        raise ValueError("Comma-separated VLAN IDs are not supported. Please create separate VLAN blocks for non-contiguous VLANs")
    if '-' in vlan_id_str:
        # Range format: "100-110"
        try:
            start, end = vlan_id_str.split('-', 1)
            start_id = int(start.strip())
            end_id = int(end.strip())
            if start_id > end_id:
                raise ValueError(f"Invalid VLAN range {vlan_id_str}: start ID must be less than or equal to end ID")
            vlan_ids.extend(range(start_id, end_id + 1))
        except ValueError as e:
            if "Comma-separated" in str(e):
                raise
            raise ValueError(f"Invalid VLAN range format '{vlan_id_str}': {str(e)}")
    else:
        # Single ID
        try:
            vlan_ids.append(int(vlan_id_str))
        except ValueError:
            raise ValueError(f"Invalid VLAN ID '{vlan_id_str}': must be an integer")
    return vlan_ids


def validate_vlan_id(vlan_id):
    """
    Validate a VLAN ID is within acceptable ranges.
    Valid range: 1-4094, excluding 4043-4047, 4094, 4095
    Args:
        vlan_id: VLAN ID to validate
    Raises:
        ValueError: If VLAN ID is invalid or reserved
    Returns:
        True if valid
    """
    reserved_vlans = [4094, 4095] + list(range(4043, 4048))
    if vlan_id < 1 or vlan_id > 4094:
        raise ValueError(f"VLAN ID {vlan_id} is out of valid range (1-4094)")
    if vlan_id in reserved_vlans:
        raise ValueError(f"VLAN ID {vlan_id} is reserved for system use (4043-4047, 4094, 4095)")
    return True


def build_vlan_sharing_config(enable_sharing, sharing_type, primary_vlan_id, multicast_policy_moid):
    """
    Build VLAN sharing configuration (common for POST and PATCH).

    Args:
        enable_sharing: Whether VLAN sharing is enabled
        sharing_type: Type of sharing (Primary, Isolated, Community)
        primary_vlan_id: Primary VLAN ID for Isolated/Community types
        multicast_policy_moid: MOID of multicast policy (if not sharing)

    Returns:
        Dictionary with SharingType, PrimaryVlanId, and optionally MulticastPolicy
    """
    config = {}

    if enable_sharing:
        config['SharingType'] = sharing_type
        config['PrimaryVlanId'] = primary_vlan_id if sharing_type in ['Isolated', 'Community'] else 0
    else:
        config['SharingType'] = 'None'
        config['PrimaryVlanId'] = 0
        if multicast_policy_moid:
            config['MulticastPolicy'] = multicast_policy_moid

    return config


def build_vlan_base_body(vlan_name, vlan_id, auto_allow_on_uplinks, is_native):
    """
    Build base VLAN API body with common fields.

    Args:
        vlan_name: Name of the VLAN
        vlan_id: VLAN ID
        auto_allow_on_uplinks: Whether to auto-allow on uplinks
        is_native: Whether this is the native VLAN

    Returns:
        Dictionary with base VLAN fields
    """
    return {
        'Name': vlan_name,
        'VlanId': vlan_id,
        'AutoAllowOnUplinks': auto_allow_on_uplinks,
        'IsNative': is_native
    }


def build_vlan_body_for_post(vlan_name, vlan_id, auto_allow_on_uplinks, is_native,
                             enable_sharing, sharing_type, primary_vlan_id,
                             multicast_policy_moid, vlan_policy_moid):
    """
    Build VLAN API body for POST (create) operations.

    Args:
        vlan_policy_moid: MOID of the parent VLAN policy (required for POST)

    Returns:
        Complete API body for VLAN creation
    """
    body = build_vlan_base_body(vlan_name, vlan_id, auto_allow_on_uplinks, is_native)
    body['EthNetworkPolicy'] = vlan_policy_moid
    body.update(build_vlan_sharing_config(enable_sharing, sharing_type, primary_vlan_id, multicast_policy_moid))
    return body


def build_vlan_body_for_patch(vlan_name, vlan_id, auto_allow_on_uplinks, is_native,
                              enable_sharing, sharing_type, primary_vlan_id, multicast_policy_moid):
    """
    Build VLAN API body for PATCH (update) operations.

    Note: Excludes EthNetworkPolicy as it cannot be changed after creation.

    Returns:
        API body for VLAN update
    """
    body = build_vlan_base_body(vlan_name, vlan_id, auto_allow_on_uplinks, is_native)
    body.update(build_vlan_sharing_config(enable_sharing, sharing_type, primary_vlan_id, multicast_policy_moid))
    return body


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        vlans=dict(type='list', elements='dict', options=dict(
            prefix=dict(type='str', required=True),
            vlan_id=dict(type='str', required=True),
            auto_allow_on_uplinks=dict(type='bool', default=True),
            enable_sharing=dict(type='bool', default=False),
            multicast_policy_name=dict(type='str'),
            sharing_type=dict(type='str', choices=['Primary', 'Isolated', 'Community']),
            primary_vlan_id=dict(type='int'),
            is_native=dict(type='bool', default=False),
            state=dict(type='str', choices=['present', 'absent'], default='present')
        ))
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    # Initialize structured response
    final_response = {
        'vlan_policy': {},
        'vlans': []
    }

    # Initialize list to track changed states from each API call
    changed_states = []

    # Resource path used to configure policy
    resource_path = '/fabric/EthNetworkPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }
    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

    intersight.configure_policy_or_profile(resource_path=resource_path)

    # Store the VLAN policy response
    final_response['vlan_policy'] = intersight.result['api_response']

    # Save the changed state and reset for next operation
    changed_states.append(intersight.result['changed'])
    intersight.result['changed'] = False

    vlan_policy_moid = None
    if intersight.module.params['state'] == 'present' and final_response['vlan_policy']:
        vlan_policy_moid = final_response['vlan_policy'].get('Moid')

    # Process VLANs if provided
    if intersight.module.params['state'] == 'present' and intersight.module.params['vlans']:
        # Check if we have a valid VLAN policy MOID before processing VLANs
        if not vlan_policy_moid:
            if intersight.module.check_mode:
                # In check mode, policy doesn't exist yet, skip VLAN processing
                final_response['vlans'] = []
            else:
                # This shouldn't happen - policy should exist before processing VLANs
                module.fail_json(msg="VLAN policy MOID is missing, verify vlan policy was created by the module")
        else:
            # Cache for multicast policy MOIDs to avoid redundant API calls
            multicast_policy_cache = {}
            total_vlans_to_create = 0

            # Build all VLAN configurations and validate
            vlan_operations = {'create': [], 'update': [], 'delete': []}

            for vlan_config in intersight.module.params['vlans']:
                # Parse VLAN ID range to get list of individual VLAN IDs
                try:
                    vlan_ids = parse_vlan_id_range(vlan_config['vlan_id'])
                except ValueError as e:
                    module.fail_json(msg=f"Error parsing vlan_id '{vlan_config['vlan_id']}': {str(e)}")

                # Validate each VLAN ID
                for vlan_id in vlan_ids:
                    try:
                        validate_vlan_id(vlan_id)
                    except ValueError as e:
                        module.fail_json(msg=str(e))

                # Extract configuration
                prefix = vlan_config['prefix']
                auto_allow_on_uplinks = vlan_config.get('auto_allow_on_uplinks')
                enable_sharing = vlan_config.get('enable_sharing')
                is_native = vlan_config.get('is_native')
                vlan_state = vlan_config.get('state', 'present')

                # Process each VLAN ID in the range
                for vlan_id in vlan_ids:
                    # Check if we exceed the maximum VLAN limit (only for VLANs being created)
                    if vlan_state == 'present':
                        total_vlans_to_create += 1
                        if total_vlans_to_create > 3000:
                            module.fail_json(msg="Total number of VLANs exceeds the maximum limit of 3000")

                    # Generate VLAN name: prefix_vlan_id
                    vlan_name = f"{prefix}_{vlan_id}"

                    # Resolve multicast policy MOID if needed
                    multicast_policy_moid = None
                    sharing_type = None
                    primary_vlan_id_value = 0

                    if enable_sharing:
                        sharing_type = vlan_config.get('sharing_type')
                        if sharing_type in ['Isolated', 'Community']:
                            if 'primary_vlan_id' not in vlan_config:
                                module.fail_json(msg=f"primary_vlan_id is required when sharing_type is {sharing_type}")
                            primary_vlan_id_value = vlan_config['primary_vlan_id']
                    else:
                        # Get multicast policy name from vlan config
                        multicast_policy_name = vlan_config.get('multicast_policy_name')
                        if not multicast_policy_name:
                            module.fail_json(msg="multicast_policy_name is required when enable_sharing is false")
                        # Check if multicast policy MOID is already cached
                        if multicast_policy_name in multicast_policy_cache:
                            multicast_policy_moid = multicast_policy_cache[multicast_policy_name]
                        else:
                            # Fetch multicast policy MOID and cache it
                            multicast_policy_moid = intersight.get_moid_by_name_and_org(
                                resource_path='/fabric/MulticastPolicies',
                                resource_name=multicast_policy_name,
                                organization_name=intersight.module.params['organization']
                            )
                            if not multicast_policy_moid:
                                module.fail_json(
                                    msg=f"Multicast policy '{multicast_policy_name}' not found in organization '{intersight.module.params['organization']}'"
                                )
                            multicast_policy_cache[multicast_policy_name] = multicast_policy_moid

                    # Check if VLAN already exists
                    custom_filter = f"Name eq '{vlan_name}' and EthNetworkPolicy.Moid eq '{vlan_policy_moid}'"
                    intersight.get_resource(
                        resource_path='/fabric/Vlans',
                        query_params={'$filter': custom_filter}
                    )

                    existing_vlan = intersight.result.get('api_response', {})
                    existing_moid = existing_vlan.get('Moid')

                    # Determine operation type
                    if vlan_state == 'present':
                        if existing_moid:
                            # VLAN exists, check if update is needed
                            # Build body for PATCH (without EthNetworkPolicy, proper object references)
                            vlan_patch_body = build_vlan_body_for_patch(
                                vlan_name=vlan_name,
                                vlan_id=vlan_id,
                                auto_allow_on_uplinks=auto_allow_on_uplinks,
                                is_native=is_native,
                                enable_sharing=enable_sharing,
                                sharing_type=sharing_type,
                                primary_vlan_id=primary_vlan_id_value,
                                multicast_policy_moid=multicast_policy_moid
                            )
                            if not compare_values(vlan_patch_body, existing_vlan):
                                vlan_operations['update'].append({
                                    'body': vlan_patch_body,
                                    'moid': existing_moid,
                                    'name': vlan_name,
                                    'filter': custom_filter
                                })
                            else:
                                # VLAN exists and matches, add to response but no change needed
                                final_response['vlans'].append(existing_vlan)
                        else:
                            # VLAN doesn't exist, needs to be created
                            # Build body for POST (includes EthNetworkPolicy)
                            vlan_post_body = build_vlan_body_for_post(
                                vlan_name=vlan_name,
                                vlan_id=vlan_id,
                                auto_allow_on_uplinks=auto_allow_on_uplinks,
                                is_native=is_native,
                                enable_sharing=enable_sharing,
                                sharing_type=sharing_type,
                                primary_vlan_id=primary_vlan_id_value,
                                multicast_policy_moid=multicast_policy_moid,
                                vlan_policy_moid=vlan_policy_moid
                            )
                            vlan_operations['create'].append({
                                'body': vlan_post_body,
                                'name': vlan_name,
                                'filter': custom_filter
                            })
                    else:  # state == 'absent'
                        if existing_moid:
                            vlan_operations['delete'].append({
                                'moid': existing_moid,
                                'name': vlan_name,
                                'body': {
                                    'VlanId': vlan_id
                                }
                            })

            # Execute bulk operations
            bulk_results = intersight.execute_bulk_operations(
                resource_path='/fabric/Vlans',
                operations_dict=vlan_operations,
                changed_states=changed_states
            )
            final_response['vlans'].extend(bulk_results)

    # Set the final structured response
    intersight.result['api_response'] = final_response

    # Set final changed state based on whether any operation resulted in a change
    intersight.result['changed'] = any(changed_states)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
