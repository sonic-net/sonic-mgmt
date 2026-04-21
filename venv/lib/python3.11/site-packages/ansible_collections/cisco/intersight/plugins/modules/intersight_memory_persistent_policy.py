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
module: intersight_memory_persistent_policy
short_description: Memory Persistent Policy configuration for Cisco Intersight
description:
  - Manages Memory Persistent Policy configuration on Cisco Intersight.
  - Configure Persistent Memory Modules (PMM) on servers including security, goals, and namespaces.
  - Supports both Intersight-managed and Operating System-managed configuration modes.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/memory/PersistentMemoryPolicy/get/).
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
    type: str
    default: default
  name:
    description:
      - The name assigned to the Memory Persistent Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Memory Persistent Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  management_mode:
    description:
      - Configuration management mode for Persistent Memory.
      - C(configured-from-intersight) - Policy settings are configured and managed from Intersight.
      - C(configured-from-operating-system) - Associated servers are managed by Operating System tools and policy settings are unavailable.
      - When set to C(configured-from-operating-system), no other configuration fields are required or used.
    type: str
    choices: [configured-from-intersight, configured-from-operating-system]
    default: configured-from-intersight
  enable_security_passphrase:
    description:
      - Enable secure passphrase for Persistent Memory Modules.
      - When enabled, requires secure_passphrase parameter.
      - Only applicable when management_mode is C(configured-from-intersight).
    type: bool
    default: false
  secure_passphrase:
    description:
      - Secure passphrase to be applied on the Persistent Memory Modules on the server.
      - Required when enable_security_passphrase is true.
      - The allowed characters are a-z, A-Z, 0-9, and special characters =, !, &, #, $, %, +, ^, @, _, *, -.
      - Only applicable when management_mode is C(configured-from-intersight).
    type: str
  enable_goal:
    description:
      - Enable goal configuration for Persistent Memory Modules.
      - The Goal configured will be applicable to all the Persistent Memory Modules.
      - Goal modification will delete all existing regions and namespaces along with their data during profile deployment.
      - New regions and namespaces will be created after goal modification.
      - Only applicable when management_mode is C(configured-from-intersight).
    type: bool
    default: true
  memory_mode_percentage:
    description:
      - Volatile memory percentage for Memory Mode.
      - Valid range is 0-100.
      - Only applicable when enable_goal is true and management_mode is C(configured-from-intersight).
    type: int
    default: 0
  persistent_memory_type:
    description:
      - Type of Persistent Memory configuration.
      - C(app-direct) - Persistent Memory Modules are combined in an interleaved set.
      - C(app-direct-non-interleaved) - Persistent Memory Modules are not interleaved.
      - Only applicable when enable_goal is true and management_mode is C(configured-from-intersight).
    type: str
    choices: [app-direct, app-direct-non-interleaved]
    default: app-direct
  retain_namespaces:
    description:
      - Retain existing Persistent Memory Namespaces.
      - If false, all existing namespaces not listed in the namespaces parameter will be deleted along with their data.
      - Only applicable when management_mode is C(configured-from-intersight).
    type: bool
    default: true
  namespaces:
    description:
      - List of Logical Namespaces to be created or modified on the server.
      - Only applicable when management_mode is C(configured-from-intersight).
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of this Namespace to be created on the server.
        type: str
        required: true
      socket_id:
        description:
          - Socket ID of the region on which this Namespace has to be created or modified.
          - Valid values are 1, 2, 3, or 4.
        type: int
        choices: [1, 2, 3, 4]
        default: 1
      socket_memory_id:
        description:
          - Socket Memory ID of the region on which this Namespace has to be created or modified.
          - Only applicable when persistent_memory_type is C(app-direct-non-interleaved).
          - Valid values are 2, 4, 6, 8, 10, or 12.
        type: int
        choices: [2, 4, 6, 8, 10, 12]
        default: 2
      capacity:
        description:
          - Capacity of this Namespace in GiB.
          - Valid range is 1 to 9223372036854775807.
        type: int
        required: true
      mode:
        description:
          - Mode of this Namespace.
        type: str
        choices: [raw, block]
        default: raw
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Memory Persistent Policy with Intersight management
  cisco.intersight.intersight_memory_persistent_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "pmem-policy-01"
    description: "Persistent Memory policy with security and namespaces"
    management_mode: configured-from-intersight
    enable_security_passphrase: true
    secure_passphrase: "SecurePass123!"
    enable_goal: true
    memory_mode_percentage: 0
    persistent_memory_type: app-direct
    retain_namespaces: true
    namespaces:
      - name: "ns1"
        socket_id: 1
        capacity: 100000
        mode: raw
      - name: "ns2"
        socket_id: 4
        capacity: 1000065
        mode: block
    state: present

- name: Create Memory Persistent Policy with non-interleaved configuration
  cisco.intersight.intersight_memory_persistent_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "pmem-policy-non-interleaved"
    description: "Non-interleaved persistent memory configuration"
    management_mode: configured-from-intersight
    enable_security_passphrase: true
    secure_passphrase: "MySecurePass123"
    enable_goal: true
    memory_mode_percentage: 0
    persistent_memory_type: app-direct-non-interleaved
    retain_namespaces: true
    namespaces:
      - name: "ns1"
        socket_id: 1
        socket_memory_id: 2
        capacity: 100000
        mode: raw
      - name: "ns2"
        socket_id: 2
        socket_memory_id: 4
        capacity: 200000
        mode: block
    state: present

- name: Create Memory Persistent Policy with OS management
  cisco.intersight.intersight_memory_persistent_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "pmem-policy-os-managed"
    description: "OS-managed persistent memory configuration"
    management_mode: configured-from-operating-system
    state: present

- name: Create Memory Persistent Policy without security passphrase
  cisco.intersight.intersight_memory_persistent_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "pmem-policy-no-security"
    description: "Policy without security passphrase"
    management_mode: configured-from-intersight
    enable_security_passphrase: false
    enable_goal: true
    memory_mode_percentage: 10
    persistent_memory_type: app-direct
    state: present

- name: Delete Memory Persistent Policy
  cisco.intersight.intersight_memory_persistent_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "pmem-policy-01"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "pmem-policy-01",
        "ObjectType": "memory.PersistentMemoryPolicy",
        "ManagementMode": "configured-from-intersight",
        "LocalSecurity": {
            "Enabled": true
        },
        "Goals": [
            {
                "MemoryModePercentage": 0,
                "PersistentMemoryType": "app-direct",
                "SocketId": "All Sockets"
            }
        ],
        "RetainNamespaces": true,
        "LogicalNamespaces": [
            {
                "Name": "ns1",
                "SocketId": 1,
                "SocketMemoryId": "Not Applicable",
                "Capacity": 100000,
                "Mode": "raw"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_namespace_capacity(capacity):
    """
    Validate namespace capacity is within acceptable range.
    """
    if capacity < 1 or capacity > 9223372036854775807:
        raise ValueError(f"Namespace capacity {capacity} is out of valid range (1-9223372036854775807 GiB)")
    return True


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        management_mode=dict(type='str', choices=['configured-from-intersight', 'configured-from-operating-system'], default='configured-from-intersight'),
        enable_security_passphrase=dict(type='bool', default=False),
        secure_passphrase=dict(type='str', no_log=True),
        enable_goal=dict(type='bool', default=True),
        memory_mode_percentage=dict(type='int', default=0),
        persistent_memory_type=dict(type='str', choices=['app-direct', 'app-direct-non-interleaved'], default='app-direct'),
        retain_namespaces=dict(type='bool', default=True),
        namespaces=dict(type='list', elements='dict', options=dict(
            name=dict(type='str', required=True),
            socket_id=dict(type='int', choices=[1, 2, 3, 4], default=1),
            socket_memory_id=dict(type='int', choices=[2, 4, 6, 8, 10, 12], default=2),
            capacity=dict(type='int', required=True),
            mode=dict(type='str', choices=['raw', 'block'], default='raw')
        ))
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_if=[
            ['enable_security_passphrase', True, ['secure_passphrase']],
        ],
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path for Memory Persistent Policy
    resource_path = '/memory/PersistentMemoryPolicies'

    # Build base API body
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Convert management mode to API format
        management_mode_value = intersight.module.params['management_mode']
        intersight.api_body['ManagementMode'] = management_mode_value

        # Only add configuration fields if managed from Intersight
        if management_mode_value == 'configured-from-intersight':
            # Add security configuration if enabled
            if intersight.module.params['enable_security_passphrase']:
                intersight.api_body['LocalSecurity'] = {
                    'Enabled': True,
                    'SecurePassphrase': intersight.module.params['secure_passphrase']
                }
            else:
                intersight.api_body['LocalSecurity'] = {
                    'Enabled': False
                }

            # Add goal configuration if enabled
            if intersight.module.params['enable_goal']:
                # Convert persistent memory type to API format
                pmem_type_value = intersight.module.params['persistent_memory_type']
                intersight.api_body['Goals'] = [
                    {
                        'MemoryModePercentage': intersight.module.params['memory_mode_percentage'],
                        'PersistentMemoryType': pmem_type_value,
                        'SocketId': 'All Sockets'
                    }
                ]

            # Add retain namespaces setting
            intersight.api_body['RetainNamespaces'] = intersight.module.params['retain_namespaces']

            # Add logical namespaces if provided
            if intersight.module.params.get('namespaces'):
                logical_namespaces = []
                pmem_type = intersight.module.params['persistent_memory_type']
                for ns in intersight.module.params['namespaces']:
                    # Validate namespace capacity
                    try:
                        validate_namespace_capacity(ns['capacity'])
                    except ValueError as e:
                        module.fail_json(msg=str(e))

                    # Determine SocketMemoryId based on persistent memory type
                    if pmem_type == 'app-direct-non-interleaved':
                        socket_memory_id = str(ns.get('socket_memory_id', 2))
                    else:
                        socket_memory_id = 'Not Applicable'

                    namespace_entry = {
                        'Name': ns['name'],
                        'SocketId': ns['socket_id'],
                        'SocketMemoryId': socket_memory_id,
                        'Capacity': ns['capacity'],
                        'Mode': ns['mode']
                    }
                    logical_namespaces.append(namespace_entry)

                intersight.api_body['LogicalNamespaces'] = logical_namespaces

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
