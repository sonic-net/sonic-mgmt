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
module: intersight_network_connectivity_policy
short_description: Network Connectivity Policy configuration for Cisco Intersight
description:
  - Manages Network Connectivity Policy configuration on Cisco Intersight.
  - A policy to configure network connectivity settings including DNS and IPv6 on Cisco Intersight managed servers.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/networkconfig/Policy/get/).
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
      - The name assigned to the Network Connectivity Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Network Connectivity Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  enable_dynamic_dns:
    description:
      - If enabled, updates the resource records to the DNS from Cisco IMC.
    type: bool
    default: false
  dynamic_dns_domain:
    description:
      - The domain name appended to a hostname for a Dynamic DNS (DDNS) update.
      - If left blank, only a hostname is sent to the DDNS update request.
      - This parameter is optional even when enable_dynamic_dns is true.
    type: str
  enable_ipv4_dns_from_dhcp:
    description:
      - Enable IPv4 DNS from DHCP.
      - If enabled, Cisco IMC retrieves the DNS server addresses from DHCP.
    type: bool
    default: false
  preferred_ipv4_dns_server:
    description:
      - IP address of the primary DNS server.
      - This is used when enable_ipv4_dns_from_dhcp is false.
    type: str
    default: "0.0.0.0"
  alternate_ipv4_dns_server:
    description:
      - IP address of the secondary DNS server.
      - This is used when enable_ipv4_dns_from_dhcp is false.
    type: str
    default: "0.0.0.0"
  enable_ipv6:
    description:
      - If enabled, allows to configure IPv6 properties.
    type: bool
    default: false
  enable_ipv6_dns_from_dhcp:
    description:
      - If enabled, Cisco IMC retrieves the DNS server addresses from DHCP.
      - Use DHCP field must be enabled for IPv6 in Cisco IMC to enable it.
    type: bool
    default: false
  preferred_ipv6_dns_server:
    description:
      - IP address of the primary DNS server.
    type: str
    default: "::"
  alternate_ipv6_dns_server:
    description:
      - IP address of the secondary DNS server.
    type: str
    default: "::"
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a Network Connectivity Policy with Dynamic DNS enabled
  cisco.intersight.intersight_network_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "DynamicDNS-Policy"
    description: "Network connectivity policy with Dynamic DNS"
    tags:
      - Key: "Site"
        Value: "DataCenter-A"
    enable_dynamic_dns: true
    dynamic_dns_domain: "company.com"
    enable_ipv4_dns_from_dhcp: true
    enable_ipv6: true
    enable_ipv6_dns_from_dhcp: true
    state: present

- name: Create a Network Connectivity Policy with static DNS servers
  cisco.intersight.intersight_network_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "StaticDNS-Policy"
    description: "Network connectivity policy with static DNS servers"
    enable_dynamic_dns: false
    enable_ipv4_dns_from_dhcp: false
    preferred_ipv4_dns_server: "8.8.8.8"
    alternate_ipv4_dns_server: "8.8.4.4"
    enable_ipv6: true
    enable_ipv6_dns_from_dhcp: false
    preferred_ipv6_dns_server: "2001:4860:4860::8888"
    alternate_ipv6_dns_server: "2001:4860:4860::8844"
    state: present

- name: Create a basic Network Connectivity Policy with defaults
  cisco.intersight.intersight_network_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "Basic-Network-Policy"
    description: "A basic network connectivity policy"
    state: present

- name: Delete a Network Connectivity Policy
  cisco.intersight.intersight_network_connectivity_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "DynamicDNS-Policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "test_network_connectivity_policy",
        "ObjectType": "networkconfig.Policy",
        "EnableDynamicDns": true,
        "DynamicDnsDomain": "company.com",
        "EnableIpv4dnsFromDhcp": true,
        "EnableIpv6": true,
        "EnableIpv6dnsFromDhcp": true,
        "Tags": [
            {
                "Key": "Site",
                "Value": "DataCenter-A"
            }
        ]
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
        enable_dynamic_dns=dict(type='bool', default=False),
        dynamic_dns_domain=dict(type='str'),
        enable_ipv4_dns_from_dhcp=dict(type='bool', default=False),
        preferred_ipv4_dns_server=dict(type='str', default='0.0.0.0'),
        alternate_ipv4_dns_server=dict(type='str', default='0.0.0.0'),
        enable_ipv6=dict(type='bool', default=False),
        enable_ipv6_dns_from_dhcp=dict(type='bool', default=False),
        preferred_ipv6_dns_server=dict(type='str', default='::'),
        alternate_ipv6_dns_server=dict(type='str', default='::')
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/networkconfig/Policies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'EnableDynamicDns': intersight.module.params['enable_dynamic_dns'],
        'EnableIpv4dnsFromDhcp': intersight.module.params['enable_ipv4_dns_from_dhcp'],
        'EnableIpv6': intersight.module.params['enable_ipv6'],
    }

    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Add fields for static DNS servers if not using DHCP
        if not intersight.module.params['enable_ipv4_dns_from_dhcp']:
            intersight.api_body['PreferredIpv4dnsServer'] = intersight.module.params['preferred_ipv4_dns_server']
            intersight.api_body['AlternateIpv4dnsServer'] = intersight.module.params['alternate_ipv4_dns_server']

        # Add IPv6 fields if enabled
        if intersight.module.params['enable_ipv6']:
            intersight.api_body['EnableIpv6dnsFromDhcp'] = intersight.module.params['enable_ipv6_dns_from_dhcp']

            # Add fields for static DNS servers if not using DHCP for IPv6
            if not intersight.module.params['enable_ipv6_dns_from_dhcp']:
                intersight.api_body['PreferredIpv6dnsServer'] = intersight.module.params['preferred_ipv6_dns_server']
                intersight.api_body['AlternateIpv6dnsServer'] = intersight.module.params['alternate_ipv6_dns_server']

        # Add Dynamic DNS fields if enabled and domain is provided
        if intersight.module.params['enable_dynamic_dns'] and intersight.module.params['dynamic_dns_domain']:
            intersight.api_body['DynamicDnsDomain'] = intersight.module.params['dynamic_dns_domain']

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
