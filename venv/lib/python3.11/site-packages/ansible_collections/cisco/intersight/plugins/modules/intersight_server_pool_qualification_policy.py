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
module: intersight_server_pool_qualification_policy
short_description: Server Pool Qualification Policy configuration for Cisco Intersight
description:
  - Manages Server Pool Qualification Policy configuration on Cisco Intersight.
  - A Server Pool Qualification Policy defines conditions to qualify servers for resource pools based on various hardware and configuration attributes.
  - Supports multiple qualifier types including Domain, Rack Server, Blade, Tag, Memory, GPU, Processor, and Network Adaptor qualifiers.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/resourcepool/QualificationPolicies/get/).
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
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Server Pool Qualification Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Server Pool Qualification Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  domain_qualifier:
    description:
      - Domain qualifier for Fabric Interconnect and domain-based qualification.
    type: dict
    suboptions:
      fabric_interconnect_pids:
        description:
          - List of Fabric Interconnect PIDs to qualify resources.
          - Qualifies resources based on the PID property of Fabric Interconnects.
        type: list
        elements: str
      domain_names:
        description:
          - List of domain names to qualify resources.
          - Qualifies resources based on the DomainName property.
        type: list
        elements: str
  rack_server_qualifier:
    description:
      - Rack server qualifier for qualifying rack-based servers.
    type: dict
    suboptions:
      rack_id_ranges:
        description:
          - List of rack ID ranges to qualify servers.
          - Each range specifies min_value and max_value for rack IDs.
        type: list
        elements: dict
        suboptions:
          min_value:
            description:
              - Minimum rack ID value (1-256).
            type: int
            required: true
          max_value:
            description:
              - Maximum rack ID value (min_value-256).
            type: int
            required: true
      pids:
        description:
          - List of rack server PIDs to qualify (maximum 20).
          - Qualifies rack servers based on their PID.
        type: list
        elements: str
      asset_tags:
        description:
          - List of asset tags to qualify servers.
          - Qualifies servers based on the AssetTag property.
        type: list
        elements: str
      user_labels:
        description:
          - List of user labels to qualify servers.
          - Qualifies servers based on the UserLabel property.
        type: list
        elements: str
  blade_qualifier:
    description:
      - Blade qualifier for qualifying blade-based servers.
    type: dict
    suboptions:
      pids:
        description:
          - List of blade server PIDs to qualify (maximum 20).
          - Qualifies blade servers based on their PID.
        type: list
        elements: str
      chassis_pids:
        description:
          - List of chassis PIDs to qualify (maximum 20).
          - Qualifies blade servers based on chassis PID.
        type: list
        elements: str
      asset_tags:
        description:
          - List of asset tags to qualify blade servers.
          - Qualifies servers based on the AssetTag property.
        type: list
        elements: str
      user_labels:
        description:
          - List of user labels to qualify blade servers.
          - Qualifies servers based on the UserLabel property.
        type: list
        elements: str
      chassis_slot_ranges:
        description:
          - List of chassis and slot ID ranges to qualify blade servers.
        type: list
        elements: dict
        suboptions:
          chassis_id_range:
            description:
              - Chassis ID range specification.
            type: dict
            required: true
            suboptions:
              min_value:
                description:
                  - Minimum chassis ID value (1-40).
                type: int
                required: true
              max_value:
                description:
                  - Maximum chassis ID value (min_value-40).
                type: int
                required: true
          slot_id_ranges:
            description:
              - List of slot ID ranges within the chassis.
              - Can only be specified if chassis_id_range is provided.
            type: list
            elements: dict
            suboptions:
              min_value:
                description:
                  - Minimum slot ID value (1-8).
                type: int
                required: true
              max_value:
                description:
                  - Maximum slot ID value (min_value-8).
                type: int
                required: true
  tag_qualifier:
    description:
      - Tag qualifier for qualifying resources based on tags.
    type: dict
    suboptions:
      server_tags:
        description:
          - List of server tags in key-value format.
        type: list
        elements: dict
        suboptions:
          key:
            description:
              - Tag key.
            type: str
            required: true
          value:
            description:
              - Tag value.
            type: str
            required: true
      domain_profile_tags:
        description:
          - List of domain profile tags in key-value format.
        type: list
        elements: dict
        suboptions:
          key:
            description:
              - Tag key.
            type: str
            required: true
          value:
            description:
              - Tag value.
            type: str
            required: true
      chassis_tags:
        description:
          - List of chassis tags in key-value format.
        type: list
        elements: dict
        suboptions:
          key:
            description:
              - Tag key.
            type: str
            required: true
          value:
            description:
              - Tag value.
            type: str
            required: true
  memory_qualifier:
    description:
      - Memory qualifier for qualifying servers based on memory specifications.
    type: dict
    suboptions:
      capacity_range:
        description:
          - Memory capacity range in GiB.
        type: dict
        suboptions:
          min_value:
            description:
              - Minimum memory capacity in GiB (1-999999).
            type: int
            required: true
          max_value:
            description:
              - Maximum memory capacity in GiB (min_value-999999).
            type: int
            required: true
      units_range:
        description:
          - Number of memory units range.
        type: dict
        suboptions:
          min_value:
            description:
              - Minimum number of memory units (1-99999).
            type: int
            required: true
          max_value:
            description:
              - Maximum number of memory units (min_value-99999).
            type: int
            required: true
  gpu_qualifier:
    description:
      - GPU qualifier for qualifying servers based on GPU specifications.
      - If not specified, a default GPU qualifier with C(servers_without_gpu) evaluation type is automatically added.
    type: dict
    suboptions:
      evaluation_type:
        description:
          - GPU evaluation type for server qualification.
          - C(servers_without_gpu) - Qualifies servers without GPUs (default).
          - C(all_servers) - Qualifies all servers regardless of GPU presence.
          - C(servers_with_gpu) - Qualifies only servers with GPUs.
        type: str
        choices: [servers_without_gpu, all_servers, servers_with_gpu]
        default: servers_without_gpu
      gpu_count_range:
        description:
          - GPU count range (only applicable when evaluation_type is servers_with_gpu).
        type: dict
        suboptions:
          min_value:
            description:
              - Minimum number of GPUs (1-16).
            type: int
            required: true
          max_value:
            description:
              - Maximum number of GPUs (min_value-16).
            type: int
            required: true
      pids:
        description:
          - List of GPU PIDs to qualify (maximum 20, only for servers_with_gpu).
        type: list
        elements: str
      vendor:
        description:
          - GPU vendor (only applicable when evaluation_type is servers_with_gpu).
        type: str
        choices: [nvidia, intel, amd]
  processor_qualifier:
    description:
      - Processor qualifier for qualifying servers based on CPU specifications.
    type: dict
    suboptions:
      cores_range:
        description:
          - CPU cores range.
        type: dict
        suboptions:
          min_value:
            description:
              - Minimum number of CPU cores (1-9999).
            type: int
            required: true
          max_value:
            description:
              - Maximum number of CPU cores (min_value-9999).
            type: int
            required: true
      speed_range:
        description:
          - CPU speed range in GHz.
        type: dict
        suboptions:
          min_value:
            description:
              - Minimum CPU speed in GHz (1-99).
            type: int
            required: true
          max_value:
            description:
              - Maximum CPU speed in GHz (min_value-99).
            type: int
            required: true
      pids:
        description:
          - List of processor PIDs to qualify (maximum 100).
        type: list
        elements: str
      vendor:
        description:
          - Processor vendor.
        type: str
        choices: [intel, amd]
  network_adaptor_qualifier:
    description:
      - Network adaptor qualifier for qualifying servers based on network adaptor count.
    type: dict
    suboptions:
      adaptors_range:
        description:
          - Number of network adaptors range.
        type: dict
        suboptions:
          min_value:
            description:
              - Minimum number of network adaptors (1-16).
            type: int
            required: true
          max_value:
            description:
              - Maximum number of network adaptors (min_value-16).
            type: int
            required: true
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create minimal Server Pool Qualification Policy
  cisco.intersight.intersight_server_pool_qualification_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "ServerPool-Minimal-Policy"
    description: "Minimal policy - GPU qualifier automatically added with servers_without_gpu"
    state: present

- name: Create Server Pool Qualification Policy with domain and rack qualifiers
  cisco.intersight.intersight_server_pool_qualification_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "ServerPool-Qual-Policy-01"
    description: "Server pool qualification with domain and rack filters"
    domain_qualifier:
      fabric_interconnect_pids:
        - ucs-fi-6454
        - ucs-fi-64108
      domain_names:
        - "AC08-6454"
    rack_server_qualifier:
      rack_id_ranges:
        - min_value: 2
          max_value: 4
        - min_value: 5
          max_value: 8
      pids:
        - "UCSC-C245-M8SX"
        - "UCSC-C220-M8S"
      asset_tags:
        - "production"
      user_labels:
        - "datacenter-a"
    state: present

- name: Create Server Pool Qualification Policy with blade and memory qualifiers
  cisco.intersight.intersight_server_pool_qualification_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "ServerPool-Blade-Policy"
    blade_qualifier:
      pids:
        - "UCSB-B480-M5"
        - "UCSB-B200-M5"
      chassis_pids:
        - "N20-C6508"
      chassis_slot_ranges:
        - chassis_id_range:
            min_value: 2
            max_value: 10
          slot_id_ranges:
            - min_value: 4
              max_value: 6
    memory_qualifier:
      capacity_range:
        min_value: 64
        max_value: 512
      units_range:
        min_value: 10
        max_value: 20
    state: present

- name: Create Server Pool Qualification Policy with GPU requirements
  cisco.intersight.intersight_server_pool_qualification_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "ServerPool-GPU-Policy"
    description: "Policy for servers with NVIDIA GPUs"
    gpu_qualifier:
      evaluation_type: servers_with_gpu
      gpu_count_range:
        min_value: 2
        max_value: 4
      vendor: nvidia
    processor_qualifier:
      cores_range:
        min_value: 16
        max_value: 64
      vendor: intel
    state: present

- name: Create Server Pool Qualification Policy with tag qualifiers
  cisco.intersight.intersight_server_pool_qualification_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "ServerPool-Tag-Policy"
    tag_qualifier:
      server_tags:
        - key: "environment"
          value: "production"
        - key: "tier"
          value: "1"
      chassis_tags:
        - key: "location"
          value: "datacenter-a"
    network_adaptor_qualifier:
      adaptors_range:
        min_value: 2
        max_value: 8
    state: present

- name: Create comprehensive Server Pool Qualification Policy
  cisco.intersight.intersight_server_pool_qualification_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Production"
    name: "ServerPool-Comprehensive-Policy"
    description: "Comprehensive qualification policy with multiple qualifiers"
    domain_qualifier:
      fabric_interconnect_pids:
        - ucs-fi-6454
    rack_server_qualifier:
      pids:
        - "UCSC-C220-M6S"
        - "UCSC-C240-M6S"
    blade_qualifier:
      pids:
        - "UCSX-210C-M7"
        - "UCSX-410C-M7"
    memory_qualifier:
      capacity_range:
        min_value: 128
        max_value: 1024
    processor_qualifier:
      cores_range:
        min_value: 32
        max_value: 128
      vendor: intel
    gpu_qualifier:
      evaluation_type: servers_without_gpu
    network_adaptor_qualifier:
      adaptors_range:
        min_value: 2
        max_value: 4
    tags:
      - Key: "Environment"
        Value: "Production"
    state: present

- name: Delete Server Pool Qualification Policy
  cisco.intersight.intersight_server_pool_qualification_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "ServerPool-Qual-Policy-01"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "ServerPool-Qual-Policy-01",
        "ObjectType": "resourcepool.QualificationPolicy",
        "Organization": {
            "Moid": "675450ee69726530014753e2",
            "ObjectType": "organization.Organization"
        },
        "Qualifiers": [
            {
                "FabricInterConnectPids": ["UCS-FI-6454", "UCS-FI-64108"],
                "DomainNames": ["AC08-6454"],
                "ObjectType": "resource.DomainQualifier"
            },
            {
                "RackIdRange": [{"MinValue": 2, "MaxValue": 4}],
                "Pids": ["UCSC-C245-M8SX"],
                "ObjectType": "resource.RackServerQualifier"
            }
        ]
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def build_domain_qualifier(domain_qualifier):
    """Build domain qualifier API body."""
    qualifier = {'ObjectType': 'resource.DomainQualifier'}

    if domain_qualifier.get('fabric_interconnect_pids'):
        # Convert lowercase choices to API format (uppercase with hyphens)
        qualifier['FabricInterConnectPids'] = [
            pid.upper() for pid in domain_qualifier['fabric_interconnect_pids']
        ]

    if domain_qualifier.get('domain_names'):
        qualifier['DomainNames'] = domain_qualifier['domain_names']

    return qualifier


def build_rack_server_qualifier(rack_server_qualifier):
    """Build rack server qualifier API body."""
    qualifier = {'ObjectType': 'resource.RackServerQualifier'}

    if rack_server_qualifier.get('rack_id_ranges'):
        qualifier['RackIdRange'] = [
            {'MinValue': range_item['min_value'], 'MaxValue': range_item['max_value']}
            for range_item in rack_server_qualifier['rack_id_ranges']
        ]

    if rack_server_qualifier.get('pids'):
        qualifier['Pids'] = rack_server_qualifier['pids']

    if rack_server_qualifier.get('asset_tags'):
        qualifier['AssetTags'] = rack_server_qualifier['asset_tags']

    if rack_server_qualifier.get('user_labels'):
        qualifier['UserLabels'] = rack_server_qualifier['user_labels']

    return qualifier


def build_blade_qualifier(blade_qualifier):
    """Build blade qualifier API body."""
    qualifier = {'ObjectType': 'resource.BladeQualifier'}

    if blade_qualifier.get('pids'):
        qualifier['Pids'] = blade_qualifier['pids']

    if blade_qualifier.get('chassis_pids'):
        qualifier['ChassisPids'] = blade_qualifier['chassis_pids']

    if blade_qualifier.get('asset_tags'):
        qualifier['AssetTags'] = blade_qualifier['asset_tags']

    if blade_qualifier.get('user_labels'):
        qualifier['UserLabels'] = blade_qualifier['user_labels']

    if blade_qualifier.get('chassis_slot_ranges'):
        chassis_slot_list = []
        for range_item in blade_qualifier['chassis_slot_ranges']:
            chassis_slot = {
                'ChassisIdRange': {
                    'MinValue': range_item['chassis_id_range']['min_value'],
                    'MaxValue': range_item['chassis_id_range']['max_value']
                }
            }
            if range_item.get('slot_id_ranges'):
                chassis_slot['SlotIdRanges'] = [
                    {'MinValue': slot['min_value'], 'MaxValue': slot['max_value']}
                    for slot in range_item['slot_id_ranges']
                ]
            chassis_slot_list.append(chassis_slot)
        qualifier['ChassisAndSlotIdRange'] = chassis_slot_list

    return qualifier


def build_tag_qualifier(tag_qualifier):
    """Build tag qualifier API body."""
    qualifier = {'ObjectType': 'resource.TagQualifier'}

    if tag_qualifier.get('server_tags'):
        qualifier['ServerTags'] = [
            {'Key': tag['key'], 'Value': tag['value']}
            for tag in tag_qualifier['server_tags']
        ]

    if tag_qualifier.get('domain_profile_tags'):
        qualifier['DomainProfileTags'] = [
            {'Key': tag['key'], 'Value': tag['value']}
            for tag in tag_qualifier['domain_profile_tags']
        ]

    if tag_qualifier.get('chassis_tags'):
        qualifier['ChassisTags'] = [
            {'Key': tag['key'], 'Value': tag['value']}
            for tag in tag_qualifier['chassis_tags']
        ]

    return qualifier


def build_memory_qualifier(memory_qualifier):
    """Build memory qualifier API body."""
    qualifier = {'ObjectType': 'resource.MemoryQualifier'}

    if memory_qualifier.get('capacity_range'):
        qualifier['MemoryCapacityRange'] = {
            'MinValue': memory_qualifier['capacity_range']['min_value'],
            'MaxValue': memory_qualifier['capacity_range']['max_value']
        }

    if memory_qualifier.get('units_range'):
        qualifier['MemoryUnitsRange'] = {
            'MinValue': memory_qualifier['units_range']['min_value'],
            'MaxValue': memory_qualifier['units_range']['max_value']
        }

    return qualifier


def build_gpu_qualifier(gpu_qualifier):
    """Build GPU qualifier API body."""
    qualifier = {'ObjectType': 'resource.GpuQualifier'}

    # Convert evaluation type to API format
    eval_type_map = {
        'servers_without_gpu': 'ServerWithoutGpu',
        'all_servers': 'Unspecified',
        'servers_with_gpu': 'ServerWithGpu'
    }
    eval_type = gpu_qualifier.get('evaluation_type', 'servers_without_gpu')
    qualifier['GpuEvaluationType'] = eval_type_map[eval_type]

    # GPU-specific fields only apply for ServerWithGpu
    if eval_type == 'servers_with_gpu':
        if gpu_qualifier.get('gpu_count_range'):
            qualifier['GpuCountRange'] = {
                'MinValue': gpu_qualifier['gpu_count_range']['min_value'],
                'MaxValue': gpu_qualifier['gpu_count_range']['max_value']
            }

        if gpu_qualifier.get('pids'):
            qualifier['Pids'] = gpu_qualifier['pids']

        if gpu_qualifier.get('vendor'):
            # Convert vendor to API format
            vendor_map = {
                'nvidia': 'NVIDIA',
                'intel': 'Intel',
                'amd': 'AMD'
            }
            qualifier['Vendor'] = vendor_map[gpu_qualifier['vendor']]

    return qualifier


def build_processor_qualifier(processor_qualifier):
    """Build processor qualifier API body."""
    qualifier = {'ObjectType': 'resource.ProcessorQualifier'}

    if processor_qualifier.get('cores_range'):
        qualifier['CpuCoresRange'] = {
            'MinValue': processor_qualifier['cores_range']['min_value'],
            'MaxValue': processor_qualifier['cores_range']['max_value']
        }

    if processor_qualifier.get('speed_range'):
        qualifier['SpeedRange'] = {
            'MinValue': processor_qualifier['speed_range']['min_value'],
            'MaxValue': processor_qualifier['speed_range']['max_value']
        }

    if processor_qualifier.get('pids'):
        qualifier['Pids'] = processor_qualifier['pids']

    if processor_qualifier.get('vendor'):
        # Convert vendor to API format
        vendor_map = {
            'intel': 'Intel(R) Corporation',
            'amd': 'AMD'
        }
        qualifier['Vendor'] = vendor_map[processor_qualifier['vendor']]

    return qualifier


def build_network_adaptor_qualifier(network_adaptor_qualifier):
    """Build network adaptor qualifier API body."""
    qualifier = {'ObjectType': 'resource.NetworkAdaptorQualifier'}

    if network_adaptor_qualifier.get('adaptors_range'):
        qualifier['AdaptorsRange'] = {
            'MinValue': network_adaptor_qualifier['adaptors_range']['min_value'],
            'MaxValue': network_adaptor_qualifier['adaptors_range']['max_value']
        }

    return qualifier


def validate_range_values(module, range_dict, range_name, min_limit, max_limit):
    """Validate that range min/max values are within limits and min <= max."""
    if not range_dict:
        return

    min_val = range_dict.get('min_value')
    max_val = range_dict.get('max_value')

    if min_val is not None and (min_val < min_limit or min_val > max_limit):
        module.fail_json(msg=f"{range_name} min_value must be between {min_limit} and {max_limit}")

    if max_val is not None and (max_val < min_limit or max_val > max_limit):
        module.fail_json(msg=f"{range_name} max_value must be between {min_limit} and {max_limit}")

    if min_val is not None and max_val is not None and min_val > max_val:
        module.fail_json(msg=f"{range_name} min_value cannot be greater than max_value")


def validate_list_length(module, list_param, max_length, param_name):
    """Validate that a list parameter does not exceed maximum length."""
    if list_param and len(list_param) > max_length:
        module.fail_json(msg=f"{param_name} cannot contain more than {max_length} items")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        domain_qualifier=dict(
            type='dict',
            options=dict(
                fabric_interconnect_pids=dict(
                    type='list',
                    elements='str'
                ),
                domain_names=dict(type='list', elements='str')
            )
        ),
        rack_server_qualifier=dict(
            type='dict',
            options=dict(
                rack_id_ranges=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        min_value=dict(type='int', required=True),
                        max_value=dict(type='int', required=True)
                    )
                ),
                pids=dict(type='list', elements='str'),
                asset_tags=dict(type='list', elements='str'),
                user_labels=dict(type='list', elements='str')
            )
        ),
        blade_qualifier=dict(
            type='dict',
            options=dict(
                pids=dict(type='list', elements='str'),
                chassis_pids=dict(type='list', elements='str'),
                asset_tags=dict(type='list', elements='str'),
                user_labels=dict(type='list', elements='str'),
                chassis_slot_ranges=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        chassis_id_range=dict(
                            type='dict',
                            required=True,
                            options=dict(
                                min_value=dict(type='int', required=True),
                                max_value=dict(type='int', required=True)
                            )
                        ),
                        slot_id_ranges=dict(
                            type='list',
                            elements='dict',
                            options=dict(
                                min_value=dict(type='int', required=True),
                                max_value=dict(type='int', required=True)
                            )
                        )
                    )
                )
            )
        ),
        tag_qualifier=dict(
            type='dict',
            options=dict(
                server_tags=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        key=dict(type='str', required=True, no_log=False),
                        value=dict(type='str', required=True)
                    )
                ),
                domain_profile_tags=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        key=dict(type='str', required=True, no_log=False),
                        value=dict(type='str', required=True)
                    )
                ),
                chassis_tags=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        key=dict(type='str', required=True, no_log=False),
                        value=dict(type='str', required=True)
                    )
                )
            )
        ),
        memory_qualifier=dict(
            type='dict',
            options=dict(
                capacity_range=dict(
                    type='dict',
                    options=dict(
                        min_value=dict(type='int', required=True),
                        max_value=dict(type='int', required=True)
                    )
                ),
                units_range=dict(
                    type='dict',
                    options=dict(
                        min_value=dict(type='int', required=True),
                        max_value=dict(type='int', required=True)
                    )
                )
            )
        ),
        gpu_qualifier=dict(
            type='dict',
            options=dict(
                evaluation_type=dict(
                    type='str',
                    choices=['servers_without_gpu', 'all_servers', 'servers_with_gpu'],
                    default='servers_without_gpu'
                ),
                gpu_count_range=dict(
                    type='dict',
                    options=dict(
                        min_value=dict(type='int', required=True),
                        max_value=dict(type='int', required=True)
                    )
                ),
                pids=dict(type='list', elements='str'),
                vendor=dict(type='str', choices=['nvidia', 'intel', 'amd'])
            )
        ),
        processor_qualifier=dict(
            type='dict',
            options=dict(
                cores_range=dict(
                    type='dict',
                    options=dict(
                        min_value=dict(type='int', required=True),
                        max_value=dict(type='int', required=True)
                    )
                ),
                speed_range=dict(
                    type='dict',
                    options=dict(
                        min_value=dict(type='int', required=True),
                        max_value=dict(type='int', required=True)
                    )
                ),
                pids=dict(type='list', elements='str'),
                vendor=dict(type='str', choices=['intel', 'amd'])
            )
        ),
        network_adaptor_qualifier=dict(
            type='dict',
            options=dict(
                adaptors_range=dict(
                    type='dict',
                    options=dict(
                        min_value=dict(type='int', required=True),
                        max_value=dict(type='int', required=True)
                    )
                )
            )
        )
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/resourcepool/QualificationPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Build qualifiers list
        qualifiers = []

        # Domain qualifier
        if module.params.get('domain_qualifier'):
            qualifiers.append(build_domain_qualifier(module.params['domain_qualifier']))

        # Rack server qualifier
        if module.params.get('rack_server_qualifier'):
            rack_qual = module.params['rack_server_qualifier']

            # Validate rack ID ranges
            if rack_qual.get('rack_id_ranges'):
                for rack_range in rack_qual['rack_id_ranges']:
                    validate_range_values(module, rack_range, 'Rack ID range', 1, 256)

            # Validate PID list length
            validate_list_length(module, rack_qual.get('pids'), 20, 'Rack server PIDs')

            qualifiers.append(build_rack_server_qualifier(rack_qual))

        # Blade qualifier
        if module.params.get('blade_qualifier'):
            blade_qual = module.params['blade_qualifier']

            # Validate PID list lengths
            validate_list_length(module, blade_qual.get('pids'), 20, 'Blade server PIDs')
            validate_list_length(module, blade_qual.get('chassis_pids'), 20, 'Chassis PIDs')

            # Validate chassis and slot ranges
            if blade_qual.get('chassis_slot_ranges'):
                for range_item in blade_qual['chassis_slot_ranges']:
                    validate_range_values(module, range_item['chassis_id_range'],
                                          'Chassis ID range', 1, 40)
                    if range_item.get('slot_id_ranges'):
                        for slot_range in range_item['slot_id_ranges']:
                            validate_range_values(module, slot_range, 'Slot ID range', 1, 8)

            qualifiers.append(build_blade_qualifier(blade_qual))

        # Tag qualifier
        if module.params.get('tag_qualifier'):
            qualifiers.append(build_tag_qualifier(module.params['tag_qualifier']))

        # Memory qualifier
        if module.params.get('memory_qualifier'):
            mem_qual = module.params['memory_qualifier']

            # Validate memory ranges
            validate_range_values(module, mem_qual.get('capacity_range'),
                                  'Memory capacity range', 1, 999999)
            validate_range_values(module, mem_qual.get('units_range'),
                                  'Memory units range', 1, 99999)

            qualifiers.append(build_memory_qualifier(mem_qual))

        # GPU qualifier
        if module.params.get('gpu_qualifier'):
            gpu_qual = module.params['gpu_qualifier']

            # Validate GPU count range
            validate_range_values(module, gpu_qual.get('gpu_count_range'),
                                  'GPU count range', 1, 16)

            # Validate GPU PIDs list length
            validate_list_length(module, gpu_qual.get('pids'), 20, 'GPU PIDs')

            # Validate GPU-specific fields only for servers_with_gpu
            if gpu_qual.get('evaluation_type') != 'servers_with_gpu':
                if gpu_qual.get('gpu_count_range') or gpu_qual.get('pids') or gpu_qual.get('vendor'):
                    module.warn('GPU count, PIDs, and vendor are only applicable when evaluation_type is servers_with_gpu')

            qualifiers.append(build_gpu_qualifier(gpu_qual))
        else:
            # Add default GPU qualifier if not specified
            default_gpu_qual = {'evaluation_type': 'servers_without_gpu'}
            qualifiers.append(build_gpu_qualifier(default_gpu_qual))

        # Processor qualifier
        if module.params.get('processor_qualifier'):
            proc_qual = module.params['processor_qualifier']

            # Validate processor ranges
            validate_range_values(module, proc_qual.get('cores_range'),
                                  'CPU cores range', 1, 9999)
            validate_range_values(module, proc_qual.get('speed_range'),
                                  'CPU speed range', 1, 99)

            # Validate processor PIDs list length
            validate_list_length(module, proc_qual.get('pids'), 100, 'Processor PIDs')

            qualifiers.append(build_processor_qualifier(proc_qual))

        # Network adaptor qualifier
        if module.params.get('network_adaptor_qualifier'):
            net_qual = module.params['network_adaptor_qualifier']

            # Validate adaptors range
            validate_range_values(module, net_qual.get('adaptors_range'),
                                  'Network adaptors range', 1, 16)

            qualifiers.append(build_network_adaptor_qualifier(net_qual))

        # Add qualifiers to API body (always present, at minimum GPU qualifier)
        intersight.api_body['Qualifiers'] = qualifiers

    # Configure the policy
    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
