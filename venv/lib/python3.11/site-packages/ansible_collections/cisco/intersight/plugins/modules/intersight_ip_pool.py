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
module: intersight_ip_pool
short_description: IP Pool configuration for Cisco Intersight
description:
  - IP Pool configuration for Cisco Intersight.
  - Used to configure IP pools settings on Cisco Intersight managed devices.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
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
      - Profiles, Policies, and Pools that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the IP Pool.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  description:
    description:
      - The user-defined description of the IP Pool.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  enable_block_level_subnet_config:
    description:
      - Determines if the "Netmask", "Gateway", "PrimaryDns" and "SecondaryDns" is globally defined or specified per IPv4 block.
      - Determines if the "Prefix", "Gateway", "PrimaryDns" and "SecondaryDns" is globally defined or specified per IPv6 block.
    type: bool
    default: false
  ipv4_config:
    description:
      - Global definition of IPv4 "Netmask", "Gateway", "PrimaryDns" and "SecondaryDns".
      - Used only when "enable_block_level_subnet_config" is false, otherwise should be defined inside ipv4_blocks.
    type: dict
    suboptions:
      netmask:
        description:
          - A subnet mask is a 32-bit number that masks an IP address and divides the IP address into network address and host address.
          - Netmask used for all IPv4 blocks.
        type: str
      gateway:
        description:
          - IP address of the default IPv4 gateway.
          - Gateway IP used for all IPv4 blocks.
        type: str
      primary_dns:
        description:
          - IP Address of the primary Domain Name System (DNS) server.
          - PrimaryDns IP used for all IPv4 blocks.
        type: str
      secondary_dns:
        description:
          - IP Address of the secondary Domain Name System (DNS) server.
          - SecondaryDns IP used for all IPv4 blocks.
        type: str
  ipv4_blocks:
    description:
      - List of the IPv4 blocks.
      - Should include the ipv4_config details per block in case "enable_block_level_subnet_config" is true
    type: list
    elements: dict
    suboptions:
      from:
        description:
          - First IPv4 address of the block.
        type: str
      size:
        description:
          - Number of identifiers this block can hold.
        type: int
      ipv4_config:
        description:
          - Block definition of IPv4 "Netmask", "Gateway", "PrimaryDns" and "SecondaryDns".
          - Used only when "enable_block_level_subnet_config" is true, otherwise should be defined globally.
        type: dict
        suboptions:
          netmask:
            description:
              - The Netmask used for the current IPv4 block.
            type: str
          gateway:
            description:
              - The Gateway IP used for the current IPv4 block.
            type: str
          primary_dns:
            description:
              - The PrimaryDns IP used for the current IPv4 block.
            type: str
          secondary_dns:
            description:
              - The SecondaryDns IP used for the current IPv4 block.
            type: str
  ipv6_config:
    description:
      - Global definition of IPv6 "Prefix", "Gateway", "PrimaryDns" and "SecondaryDns".
      - Used only when "enable_block_level_subnet_config" is false, otherwise should be defined inside ipv6_blocks.
    type: dict
    suboptions:
      prefix:
        description:
          - A prefix length which masks the IP address and divides the IP address into network address and host address.
          - Prefix used for all IPv6 blocks.
        type: str
      gateway:
        description:
          - IP address of the default IPv6 gateway.
          - Gateway IP used for all IPv6 blocks.
        type: str
      primary_dns:
        description:
          - IP Address of the primary Domain Name System (DNS) server.
          - PrimaryDns IP used for all IPv6 blocks.
        type: str
      secondary_dns:
        description:
          - IP Address of the secondary Domain Name System (DNS) server.
          - SecondaryDns IP used for all IPv6 blocks.
        type: str
  ipv6_blocks:
    description:
      - Define the IPv6 blocks.
      - Should include the ipv6_config details per block in case "enable_block_level_subnet_config" is true
    type: list
    elements: dict
    suboptions:
      from:
        description:
          - The initial IP address for the IPv6 block.
        type: str
      size:
        description:
          - The number of IPs in the block.
        type: int
      ipv6_config:
        description:
          - Block definition of IPv6 "Prefix", "Gateway", "PrimaryDns" and "SecondaryDns".
          - Used only when "enable_block_level_subnet_config" is true, otherwise should be defined globally.
        type: dict
        suboptions:
          prefix:
            description:
              - The Prefix used for the current IPv6 block.
            type: int
          gateway:
            description:
              - The Gateway IP used for the current IPv6 block.
            type: str
          primary_dns:
            description:
              - The PrimaryDns IP used for the current IPv6 block.
            type: str
          secondary_dns:
            description:
              - The SecondaryDns IP used for the current IPv6 block.
            type: str
author:
  - Shahar Golshani (@sgolshan)
'''

EXAMPLES = r'''
- name: Configure IP Pool with global config
  cisco.intersight.intersight_ip_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-ip-pool
    description: IP Pool for lab use
    ipv4_config:
      netmask: "255.255.255.0"
      gateway: "172.17.116.1"
      primary_dns: "172.17.116.2"
      secondary_dns: "172.17.116.3"
    ipv4_blocks:
      - from: "172.17.116.32"
        size: 16
      - from: "172.17.116.64"
        size: 16
    ipv6_config:
      prefix: 64
      gateway: "2001:db8::1"
      primary_dns: "2001:4860:4860::8888"
      secondary_dns: "2001:4860:4860::8844"
    ipv6_blocks:
      - from: "2001:db8::2"
        size: 64
      - from: "2001:db8::42"
        size: 64
    tags:
      - Key: Site
        Value: RCDN


- name: Configure IP Pool with block level config
  cisco.intersight.intersight_ip_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-ip-pool
    description: IP Pool for lab use
    enable_block_level_subnet_config: true
    ipv4_blocks:
      - from: "172.17.116.32"
        size: 16
        ipv4_config:
          netmask: "255.255.255.0"
          gateway: "172.17.116.1"
          primary_dns: "172.17.116.2"
          secondary_dns: "172.17.116.3"
      - from: "172.17.117.32"
        size: 16
        ipv4_config:
          netmask: "255.255.255.0"
          gateway: "172.17.117.1"
          primary_dns: "172.17.117.2"
          secondary_dns: "172.17.117.3"
    ipv6_blocks:
      - from: "2001:db8::2"
        size: 64
        ipv6_config:
          prefix: 64
          gateway: "2001:db8::1"
          primary_dns: "2001:4860:4860::8888"
          secondary_dns: "2001:4860:4860::8844"
      - from: "fd12:3456:789a::1"
        size: 64
        ipv6_config:
          prefix: 64
          gateway: "fd12:3456:789a::1"
          primary_dns: "2606:4700:4700::1111"
          secondary_dns: "2606:4700:4700::1001"
    tags:
      - Key: Site
        Value: RCDN


- name: Delete IP Pool
  cisco.intersight.intersight_ip_pool:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-ip-pool
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "AccountMoid": "",
        "Ancestors": [],
        "Assigned": 0,
        "AssignmentOrder": "sequential",
        "ClassId": "ippool.Pool",
        "CreateTime": "",
        "Description": "IP Pool for lab use",
        "DomainGroupMoid": "",
        "EnableBlockLevelSubnetConfig": true,
        "IpV4Blocks": [],
        "IpV4Config": {},
        "IpV6Blocks": [],
        "IpV6Config": {},
        "ModTime": "",
        "Moid": "",
        "Name": "lab-ip-pool",
        "ObjectType": "ippool.Pool",
        "Organization": {},
        "Owners": [],
        "PermissionResources": [],
        "Reservations": [],
        "Reserved": 0,
        "ShadowPools": [],
        "SharedScope": "",
        "Size": 160,
        "Tags": [
            {
                "Key": "Site",
                "Value": "RCDN"
            }
        ],
        "V4Assigned": 0,
        "V4Size": 32,
        "V6Assigned": 0,
        "V6Size": 128
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enable_block_level_subnet_config=dict(type='bool', default=False),
        ipv4_config=dict(type='dict'),
        ipv4_blocks=dict(type='list', elements='dict'),
        ipv6_config=dict(type='dict'),
        ipv6_blocks=dict(type='list', elements='dict'),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/ippool/Pools'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'EnableBlockLevelSubnetConfig': intersight.module.params['enable_block_level_subnet_config'],
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Validate that at least one of ipv4_blocks/ipv6_blocks was passed. We don't mark it as required in order to support absent.
        if not intersight.module.params['ipv4_blocks'] and not intersight.module.params['ipv6_blocks']:
            module.fail_json(msg="at least one of ipv4_blocks/ipv6_blocks parameters must be provided and contain at least one block when state is present")
        # Validate that when enable_block_level_subnet_config is true, ipv4_blocks/ipv6_blocks contains ipv4_config/ipv6_config.
        if intersight.module.params['enable_block_level_subnet_config']:
            if intersight.module.params['ipv4_blocks']:
                for block in intersight.module.params['ipv4_blocks']:
                    if "ipv4_config" not in block:
                        module.fail_json(msg="a block in ipv4_blocks is missing ipv4_config")
            if intersight.module.params['ipv6_blocks']:
                for block in intersight.module.params['ipv6_blocks']:
                    if "ipv6_config" not in block:
                        module.fail_json(msg="a block in ipv6_blocks is missing ipv6_config")
        # Validate that when enable_block_level_subnet_config is false, ipv4_blocks/ipv6_blocks has a global ipv4_config/ipv6_config.
        else:
            if (intersight.module.params['ipv4_blocks'] is None) != (intersight.module.params['ipv4_config'] is None):
                module.fail_json(msg="when enable_block_level_subnet_config is false, ipv4_blocks should be configured with global ipv4_config")
            if (intersight.module.params['ipv6_blocks'] is None) != (intersight.module.params['ipv6_config'] is None):
                module.fail_json(msg="when enable_block_level_subnet_config is false, ipv6_blocks should be configured with global ipv6_config")

        IpV4Blocks = []
        if intersight.module.params['ipv4_blocks']:
            for v4_block in intersight.module.params['ipv4_blocks']:
                block = {}
                block['From'] = v4_block['from']
                block['Size'] = v4_block['size']
                if 'ipv4_config' in v4_block:
                    block['IpV4Config'] = {
                        'Netmask': v4_block['ipv4_config']['netmask'],
                        'Gateway': v4_block['ipv4_config']['gateway'],
                        'PrimaryDns': v4_block['ipv4_config']['primary_dns'],
                        'SecondaryDns': v4_block['ipv4_config']['secondary_dns']
                    }
                IpV4Blocks.append(block)
        intersight.api_body['IpV4Blocks'] = IpV4Blocks

        IpV6Blocks = []
        if intersight.module.params['ipv6_blocks']:
            for v6_block in intersight.module.params['ipv6_blocks'] :
                block = {}
                block['From'] = v6_block['from']
                block['Size'] = v6_block['size']
                if 'ipv6_config' in v6_block:
                    block['IpV6Config'] = {
                        'Prefix': v6_block['ipv6_config']['prefix'],
                        'Gateway': v6_block['ipv6_config']['gateway'],
                        'PrimaryDns': v6_block['ipv6_config']['primary_dns'],
                        'SecondaryDns': v6_block['ipv6_config']['secondary_dns']
                    }
                IpV6Blocks.append(block)
        intersight.api_body['IpV6Blocks'] = IpV6Blocks

        if not intersight.module.params['enable_block_level_subnet_config']:
            if intersight.module.params['ipv4_config']:
                intersight.api_body['IpV4Config'] = {
                    'Netmask': intersight.module.params['ipv4_config']['netmask'],
                    'Gateway': intersight.module.params['ipv4_config']['gateway'],
                    'PrimaryDns': intersight.module.params['ipv4_config']['primary_dns'],
                    'SecondaryDns': intersight.module.params['ipv4_config']['secondary_dns'],
                }
            else:
                intersight.api_body['IpV4Config'] = None

            if intersight.module.params['ipv6_config']:
                intersight.api_body['IpV6Config'] = {
                    'Prefix': intersight.module.params['ipv6_config']['prefix'],
                    'Gateway': intersight.module.params['ipv6_config']['gateway'],
                    'PrimaryDns': intersight.module.params['ipv6_config']['primary_dns'],
                    'SecondaryDns': intersight.module.params['ipv6_config']['secondary_dns'],
                }
            else:
                intersight.api_body['IpV6Config'] = None

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
