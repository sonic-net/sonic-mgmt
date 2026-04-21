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
module: intersight_storage_policy_info
short_description: Gather information about Storage Policies in Cisco Intersight
description:
  - Gather information about Storage Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all Storage Policies will be returned.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the Storage Policy belongs to.
    type: str
  name:
    description:
      - The name of the Storage Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific Storage Policy by name
  cisco.intersight.intersight_storage_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "basic-storage-policy"

- name: Fetch all Storage Policies in a specific Organization
  cisco.intersight.intersight_storage_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"

- name: Fetch all Storage Policies
  cisco.intersight.intersight_storage_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": [
    {
        "Name": "basic-storage-policy",
        "ObjectType": "storage.StoragePolicy",
        "UseJbodForVdCreation": true,
        "UnusedDisksState": "NoChange",
        "DefaultDriveMode": "UnconfiguredGood",
        "ControllerAttachedNvmeSlots": "",
        "DirectAttachedNvmeSlots": "",
        "SecureJbods": "",
        "M2VirtualDrive": {
            "Enable": false,
            "ControllerSlot": "MSTOR-RAID-1",
            "Name": "MStorBootVd"
        },
        "Raid0Drive": {
            "Enable": false,
            "DriveSlots": "",
            "VirtualDrivePolicy": {
                "StripSize": 64,
                "AccessPolicy": "Default",
                "ReadPolicy": "Default",
                "WritePolicy": "Default",
                "DriveCache": "Default"
            }
        },
        "DriveGroups": [
            {
                "Name": "raid0-group",
                "RaidLevel": "Raid0",
                "SecureDriveGroup": false,
                "ManualDriveGroup": {
                    "SpanGroups": [
                        {
                            "Slots": "1,2"
                        }
                    ]
                },
                "VirtualDrives": [
                    {
                        "Name": "raid0-vd",
                        "Size": 1024,
                        "ExpandToAvailable": false,
                        "BootDrive": true,
                        "VirtualDrivePolicy": {
                            "StripSize": 128,
                            "AccessPolicy": "ReadWrite",
                            "ReadPolicy": "ReadAhead",
                            "WritePolicy": "WriteBackGoodBbu",
                            "DriveCache": "Enable"
                        }
                    }
                ]
            }
        ],
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    },
    {
        "Name": "m2-enabled-storage-policy",
        "ObjectType": "storage.StoragePolicy",
        "UseJbodForVdCreation": true,
        "UnusedDisksState": "NoChange",
        "DefaultDriveMode": "UnconfiguredGood",
        "ControllerAttachedNvmeSlots": "",
        "DirectAttachedNvmeSlots": "",
        "SecureJbods": "",
        "M2VirtualDrive": {
            "Enable": true,
            "ControllerSlot": "MSTOR-RAID-1",
            "Name": "MStorBootVd"
        },
        "Raid0Drive": {
            "Enable": false,
            "DriveSlots": "",
            "VirtualDrivePolicy": {
                "StripSize": 64,
                "AccessPolicy": "Default",
                "ReadPolicy": "Default",
                "WritePolicy": "Default",
                "DriveCache": "Default"
            }
        },
        "Tags": [
            {
                "Key": "Site",
                "Value": "Datacenter1"
            }
        ]
    }
  ]
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        organization=dict(type='str'),
        name=dict(type='str')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    resource_path = '/storage/StoragePolicies'

    query_params = intersight.set_query_params()

    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    # Fetch drive groups for each storage policy
    storage_policies = intersight.result['api_response']
    if isinstance(storage_policies, list):
        for policy in storage_policies:
            if policy.get('Moid'):
                # Fetch drive groups for this policy using StoragePolicy.Moid filter
                drive_groups_query_params = {
                    '$filter': f"StoragePolicy.Moid eq '{policy['Moid']}'"
                }

                # Create a temporary intersight instance for drive groups query
                temp_intersight = IntersightModule(module)
                temp_intersight.get_resource(
                    resource_path='/storage/DriveGroups',
                    query_params=drive_groups_query_params,
                    return_list=True
                )

                # Add drive groups to the policy
                policy['DriveGroups'] = temp_intersight.result.get('api_response', [])
    elif isinstance(storage_policies, dict) and storage_policies.get('Moid'):
        # Single policy case
        drive_groups_query_params = {
            '$filter': f"StoragePolicy.Moid eq '{storage_policies['Moid']}'"
        }

        # Create a temporary intersight instance for drive groups query
        temp_intersight = IntersightModule(module)
        temp_intersight.get_resource(
            resource_path='/storage/DriveGroups',
            query_params=drive_groups_query_params,
            return_list=True
        )

        # Add drive groups to the policy
        storage_policies['DriveGroups'] = temp_intersight.result.get('api_response', [])

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
