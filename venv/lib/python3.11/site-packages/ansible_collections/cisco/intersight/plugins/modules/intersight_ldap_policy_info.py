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
module: intersight_ldap_policy_info
short_description: Gather information about LDAP Policies in Cisco Intersight
description:
  - Gather information about LDAP Policies in L(Cisco Intersight,https://intersight.com).
  - Information can be filtered by O(organization) and O(name).
  - If no filters are passed, all LDAP Policies will be returned.
  - This module retrieves LDAP policy details including associated groups and providers.
extends_documentation_fragment: intersight
options:
  organization:
    description:
      - The name of the organization the LDAP Policy belongs to.
    type: str
  name:
    description:
      - The name of the LDAP Policy to gather information from.
    type: str
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Fetch a specific LDAP Policy by name
  cisco.intersight.intersight_ldap_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "ldap-dns-policy"

- name: Fetch all LDAP Policies in a specific Organization
  cisco.intersight.intersight_ldap_policy_info:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "org_test"

- name: Fetch all LDAP Policies
  cisco.intersight.intersight_ldap_policy_info:
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
        "Name": "ldap-dns-policy",
        "ObjectType": "iam.LdapPolicy",
        "Enabled": true,
        "BaseProperties": {
            "BaseDn": "dc=example,dc=com",
            "Domain": "example.com",
            "Timeout": 30,
            "EnableEncryption": true,
            "BindMethod": "LoginCredentials",
            "Filter": "sAMAccountName",
            "GroupAttribute": "memberOf",
            "Attribute": "CiscoAvPair",
            "EnableGroupAuthorization": true,
            "EnableNestedGroupSearch": true,
            "NestedGroupSearchDepth": 64
        },
        "EnableDns": true,
        "DnsParameters": {
            "Source": "Configured",
            "SearchDomain": "example.com",
            "SearchForest": "example.com"
        },
        "UserSearchPrecedence": "LocalUserDb",
        "Groups": [
            {
                "Name": "admin-group",
                "ObjectType": "iam.LdapGroup",
                "GroupDn": "cn=admins,ou=groups,dc=example,dc=com",
                "Domain": "example.com",
                "Moid": "5dee1d736972652d321d26c5"
            },
            {
                "Name": "readonly-group",
                "ObjectType": "iam.LdapGroup",
                "GroupDn": "cn=readers,ou=groups,dc=example,dc=com",
                "Domain": "",
                "Moid": "5dee1d736972652d321d26c6"
            }
        ],
        "Providers": [],
        "Organization": {
            "Name": "default",
            "Moid": "5dee1d736972652d321d26b5",
            "ObjectType": "organization.Organization"
        },
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    },
    {
        "Name": "ldap-provider-policy",
        "ObjectType": "iam.LdapPolicy",
        "Enabled": true,
        "BaseProperties": {
            "BaseDn": "dc=company,dc=local",
            "Domain": "company.local",
            "Timeout": 0,
            "EnableEncryption": false,
            "BindMethod": "Anonymous",
            "Filter": "sAMAccountName",
            "GroupAttribute": "memberOf",
            "Attribute": "CiscoAvPair",
            "EnableGroupAuthorization": false,
            "EnableNestedGroupSearch": false
        },
        "EnableDns": false,
        "UserSearchPrecedence": "LocalUserDb",
        "Groups": [
            {
                "Name": "users-group",
                "ObjectType": "iam.LdapGroup",
                "GroupDn": "cn=users,ou=groups,dc=company,dc=local",
                "Domain": "",
                "Moid": "5dee1d736972652d321d26c7"
            }
        ],
        "Providers": [
            {
                "Server": "10.10.10.10",
                "Port": 389,
                "Vendor": "OpenLDAP",
                "ObjectType": "iam.LdapProvider",
                "Moid": "5dee1d736972652d321d26c8"
            },
            {
                "Server": "10.10.10.11",
                "Port": 389,
                "Vendor": "OpenLDAP",
                "ObjectType": "iam.LdapProvider",
                "Moid": "5dee1d736972652d321d26c9"
            }
        ],
        "Organization": {
            "Name": "default",
            "Moid": "5dee1d736972652d321d26b5",
            "ObjectType": "organization.Organization"
        },
        "Tags": []
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

    # Initialize the Intersight module
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to fetch info
    resource_path = '/iam/LdapPolicies'

    # Set query parameters
    query_params = intersight.set_query_params()

    # Get LDAP policies
    intersight.get_resource(
        resource_path=resource_path,
        query_params=query_params,
        return_list=True
    )

    # Fetch LDAP groups and providers for each LDAP policy
    ldap_policies = intersight.result['api_response']
    if isinstance(ldap_policies, list):
        for policy in ldap_policies:
            if policy.get('Moid'):
                # Fetch LDAP groups for this policy
                groups_query_params = {
                    '$filter': f"LdapPolicy.Moid eq '{policy['Moid']}'"
                }
                temp_intersight_groups = IntersightModule(module)
                temp_intersight_groups.get_resource(
                    resource_path='/iam/LdapGroups',
                    query_params=groups_query_params,
                    return_list=True
                )
                policy['Groups'] = temp_intersight_groups.result.get('api_response', [])

                # Fetch LDAP providers for this policy
                providers_query_params = {
                    '$filter': f"LdapPolicy.Moid eq '{policy['Moid']}'"
                }
                temp_intersight_providers = IntersightModule(module)
                temp_intersight_providers.get_resource(
                    resource_path='/iam/LdapProviders',
                    query_params=providers_query_params,
                    return_list=True
                )
                policy['Providers'] = temp_intersight_providers.result.get('api_response', [])

    elif isinstance(ldap_policies, dict) and ldap_policies.get('Moid'):
        # Single policy case
        groups_query_params = {
            '$filter': f"LdapPolicy.Moid eq '{ldap_policies['Moid']}'"
        }
        temp_intersight_groups = IntersightModule(module)
        temp_intersight_groups.get_resource(
            resource_path='/iam/LdapGroups',
            query_params=groups_query_params,
            return_list=True
        )
        ldap_policies['Groups'] = temp_intersight_groups.result.get('api_response', [])

        # Fetch LDAP providers for this policy
        providers_query_params = {
            '$filter': f"LdapPolicy.Moid eq '{ldap_policies['Moid']}'"
        }
        temp_intersight_providers = IntersightModule(module)
        temp_intersight_providers.get_resource(
            resource_path='/iam/LdapProviders',
            query_params=providers_query_params,
            return_list=True
        )
        ldap_policies['Providers'] = temp_intersight_providers.result.get('api_response', [])

    # Exit the module
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
