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
module: intersight_ldap_policy
short_description: Manage LDAP Policies for Cisco Intersight
description:
  - Create, update, and delete LDAP Policies on Cisco Intersight.
  - Manage LDAP groups and providers associated with LDAP policies.
  - LDAP policies enable authentication of Cisco IMC users using an LDAP server.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/iam/LdapPolicy/get/).
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
      - The name assigned to the LDAP Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the LDAP Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  enable_ldap:
    description:
      - If enabled, LDAP server performs authentication.
    type: bool
    default: true
  base_dn:
    description:
      - Base Distinguished Name (DN).
      - Starting point from where server will search for users and groups.
      - Required when state is present.
    type: str
  domain:
    description:
      - The IPv4 domain that all users must be in.
      - Required when state is present.
    type: str
  timeout:
    description:
      - LDAP authentication timeout duration, in seconds.
      - Valid range is 0-180.
    type: int
    default: 0
  enable_encryption:
    description:
      - If enabled, the endpoint encrypts all information it sends to the LDAP server.
    type: bool
    default: false
  bind_method:
    description:
      - Authentication method to access LDAP servers.
      - C(logincredentials) uses the user credentials entered at login.
      - C(anonymous) uses no credentials to access the LDAP server.
      - C(configuredcredentials) uses a specific set of credentials configured for the LDAP server.
    type: str
    choices: [logincredentials, anonymous, configuredcredentials]
    default: logincredentials
  bind_dn:
    description:
      - Distinguished Name (DN) of the user, that is used to authenticate against LDAP servers.
      - Required when bind_method is configuredcredentials.
    type: str
  password:
    description:
      - The password of the user for initial bind process.
      - Can have any character except spaces, tabs, line breaks.
      - Cannot be more than 254 characters.
      - Required when bind_method is configuredcredentials.
    type: str
  filter:
    description:
      - Criteria to identify entries in search requests.
      - Required when state is present.
    type: str
  group_attribute:
    description:
      - Groups to which an LDAP entry belongs.
      - Required when state is present.
    type: str
  attribute:
    description:
      - Role and locale information of the user.
      - Required when state is present.
    type: str
  group_authorization:
    description:
      - If enabled, user authorization is also done at the group level for LDAP users not in the local user database.
    type: bool
    default: false
  nested_group_search:
    description:
      - If enabled, an extended search walks the chain of ancestry all the way to the root.
      - Returns all the groups and subgroups, each of those groups belong to recursively.
    type: bool
    default: false
  nested_group_search_depth:
    description:
      - Search depth to look for a nested LDAP group in an LDAP group map.
      - Valid range is 1-128.
      - Only applicable when nested_group_search is true.
    type: int
    default: 128
  enable_dns:
    description:
      - Enables DNS to access LDAP servers.
      - When enabled, LDAP providers cannot be specified (DNS discovery is used instead).
      - When disabled, at least one LDAP provider must be configured.
    type: bool
    default: false
  dns_source:
    description:
      - Source of the domain name used for the DNS SRV request.
      - C(extracted) extracts the domain name from the login ID entered by the user.
      - C(configured) uses the configured search domain.
      - C(configuredextracted) uses configured search domain first, then extracted.
      - Only applicable when enable_dns is true.
    type: str
    choices: [extracted, configured, configuredextracted]
    default: extracted
  search_domain:
    description:
      - Domain name that acts as a source for a DNS query.
      - Required when dns_source is configured or configuredextracted.
    type: str
  search_forest:
    description:
      - Forest name that acts as a source for a DNS query.
      - Required when dns_source is configured or configuredextracted.
    type: str
  user_search_precedence:
    description:
      - Search precedence between local user database and LDAP user database.
      - C(localuserdb) searches local user database first.
      - C(ldapuserdb) searches LDAP user database first.
    type: str
    choices: [localuserdb, ldapuserdb]
    default: localuserdb
  ldap_groups:
    description:
      - List of LDAP groups to be created and attached to the LDAP policy.
      - Each group defines the mapping between LDAP server groups and Intersight roles.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - LDAP Group name in the LDAP server database.
        type: str
        required: true
      state:
        description:
          - Whether to create/update or delete the LDAP group.
        type: str
        choices: [present, absent]
        default: present
      group_dn:
        description:
          - LDAP Group DN in the LDAP server database.
          - Required when state is present.
        type: str
      domain:
        description:
          - LDAP server domain the Group resides in.
        type: str
      role:
        description:
          - Role assigned to all users in this LDAP server group.
          - C(admin) provides full administrative access.
          - C(readonly) provides read-only access.
          - C(user) provides standard user access.
          - Only 'admin' role is supported in domain.
          - Required when state is present.
        type: str
        choices: [admin, readonly, user]
        default: admin
  ldap_providers:
    description:
      - List of LDAP providers (servers) to be created and attached to the LDAP policy.
      - Providers define the LDAP servers to connect to.
      - Cannot be specified when enable_dns is true (DNS discovery is used instead).
      - Required when enable_dns is false (at least one provider must be specified).
    type: list
    elements: dict
    suboptions:
      server:
        description:
          - IP address or hostname of the LDAP server.
          - Required when state is present.
        type: str
        required: true
      state:
        description:
          - Whether to create/update or delete the LDAP provider.
        type: str
        choices: [present, absent]
        default: present
      port:
        description:
          - Port number on which the LDAP server is listening.
        type: int
        default: 389
      vendor:
        description:
          - Type of LDAP server.
          - C(openldap) for OpenLDAP servers.
          - C(msad) for Microsoft Active Directory.
        type: str
        choices: [openldap, msad]
        default: openldap
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create LDAP Policy with DNS enabled
  cisco.intersight.intersight_ldap_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "ldap-dns-policy"
    description: "LDAP policy using DNS for server discovery"
    enable_ldap: true
    base_dn: "dc=example,dc=com"
    domain: "example.com"
    timeout: 30
    enable_encryption: true
    bind_method: "logincredentials"
    filter: "sAMAccountName"
    group_attribute: "memberOf"
    attribute: "CiscoAvPair"
    group_authorization: true
    nested_group_search: true
    nested_group_search_depth: 64
    enable_dns: true
    dns_source: "configured"
    search_domain: "example.com"
    search_forest: "example.com"
    user_search_precedence: "localuserdb"
    ldap_groups:
      - name: "admin-group"
        group_dn: "cn=admins,ou=groups,dc=example,dc=com"
        domain: "example.com"
        role: "admin"
      - name: "readonly-group"
        group_dn: "cn=readers,ou=groups,dc=example,dc=com"
        role: "readonly"
    tags:
      - Key: "Environment"
        Value: "Production"
    state: present

- name: Create LDAP Policy with providers
  cisco.intersight.intersight_ldap_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "ldap-provider-policy"
    description: "LDAP policy with specific servers"
    enable_ldap: true
    base_dn: "company"
    domain: "company.local"
    timeout: 0
    enable_encryption: false
    bind_method: "anonymous"
    filter: "sAMAccountName"
    group_attribute: "memberOf"
    attribute: "CiscoAvPair"
    group_authorization: false
    nested_group_search: false
    enable_dns: false
    user_search_precedence: "localuserdb"
    ldap_providers:
      - server: "10.10.10.10"
        port: 389
        vendor: "openldap"
      - server: "10.10.10.11"
        port: 389
        vendor: "openldap"
    ldap_groups:
      - name: "users-group"
        group_dn: "company"
        role: "user"
    state: present

- name: Create LDAP Policy with configured credentials
  cisco.intersight.intersight_ldap_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "ldap-configured-creds"
    description: "LDAP policy with configured bind credentials"
    enable_ldap: true
    base_dn: "dc=corp,dc=net"
    domain: "corp.net"
    timeout: 60
    enable_encryption: true
    bind_method: "configuredcredentials"
    bind_dn: "cn=admin,dc=corp,dc=net"
    password: "SecurePassword123"
    filter: "uid"
    group_attribute: "gidNumber"
    attribute: "description"
    group_authorization: true
    nested_group_search: true
    nested_group_search_depth: 128
    enable_dns: false
    user_search_precedence: "ldapuserdb"
    ldap_providers:
      - server: "ldap.corp.net"
        port: 636
        vendor: "msad"
    ldap_groups:
      - name: "administrators"
        group_dn: "cn=administrators,ou=groups,dc=corp,dc=net"
        domain: "corp.net"
        role: "admin"
    state: present

- name: Update LDAP Policy - manage group states
  cisco.intersight.intersight_ldap_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "ldap-dns-policy"
    description: "Updated LDAP policy"
    enable_ldap: true
    base_dn: "dc=example,dc=com"
    domain: "example.com"
    filter: "sAMAccountName"
    group_attribute: "memberOf"
    attribute: "CiscoAvPair"
    enable_dns: true
    ldap_groups:
      - name: "admin-group"
        group_dn: "cn=admins,ou=groups,dc=example,dc=com"
        role: "admin"
        state: present
      - name: "old-group"
        state: absent
      - name: "new-group"
        group_dn: "cn=new,ou=groups,dc=example,dc=com"
        role: "user"
        state: present
    state: present

- name: Delete LDAP Policy
  cisco.intersight.intersight_ldap_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "old-ldap-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
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
                "GroupDn": "cn=admins,ou=groups,dc=example,dc=com",
                "Domain": "example.com"
            }
        ],
        "Providers": []
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_input(module):
    """
    Validate module input parameters.
    """
    if module.params['state'] == 'present':
        required_fields = ['base_dn', 'domain', 'filter', 'group_attribute', 'attribute']
        for field in required_fields:
            if not module.params.get(field):
                module.fail_json(msg=f"{field} is required when state is 'present'")
        if module.params['bind_method'] == 'configuredcredentials':
            if not module.params.get('bind_dn'):
                module.fail_json(msg="bind_dn is required when bind_method is 'configuredcredentials'")
            if not module.params.get('password'):
                module.fail_json(msg="password is required when bind_method is 'configuredcredentials'")
        if module.params['enable_dns']:
            if module.params['dns_source'] in ['configured', 'configuredextracted']:
                if not module.params.get('search_domain'):
                    module.fail_json(msg="search_domain is required when dns_source is 'configured' or 'configuredextracted'")
                if not module.params.get('search_forest'):
                    module.fail_json(msg="search_forest is required when dns_source is 'configured' or 'configuredextracted'")
        if module.params['timeout'] < 0 or module.params['timeout'] > 180:
            module.fail_json(msg="timeout must be between 0 and 180 seconds")
        if module.params['nested_group_search']:
            depth = module.params['nested_group_search_depth']
            if depth < 1 or depth > 128:
                module.fail_json(msg="nested_group_search_depth must be between 1 and 128")

        ldap_groups = module.params.get('ldap_groups') or []
        for group in ldap_groups:
            if group.get('state', 'present') == 'present':
                if not group.get('group_dn'):
                    module.fail_json(msg=f"group_dn is required for LDAP group '{group['name']}' when state is 'present'")
                if not group.get('role'):
                    module.fail_json(msg=f"role is required for LDAP group '{group['name']}' when state is 'present'")
        if module.params['enable_dns']:
            if module.params.get('ldap_providers'):
                module.fail_json(msg="ldap_providers cannot be specified when enable_dns is true. DNS discovery is used instead of explicit providers.")
        else:
            ldap_providers = module.params.get('ldap_providers') or []
            if not ldap_providers:
                module.fail_json(msg="ldap_providers is required when enable_dns is false. Specify at least one LDAP server.")
            for provider in ldap_providers:
                if provider.get('state', 'present') == 'present':
                    if not provider.get('server'):
                        module.fail_json(msg="server is required for LDAP provider when state is 'present'")


def get_endpoint_role_moid(intersight, role_name):
    """
    Get EndPointRole MOID by role name.
    """
    intersight.get_resource(
        resource_path='/iam/EndPointRoles',
        query_params={
            '$filter': f"Name eq '{role_name}' and Type eq 'IMC'",
            '$select': 'Moid'
        }
    )
    return intersight.result['api_response'].get('Moid')


def build_ldap_group_api_body(intersight, module, group_config, ldap_policy_moid):
    """
    Build LDAP group API body.
    """
    role_name = group_config['role']
    endpoint_role_moid = get_endpoint_role_moid(intersight, role_name)
    if not endpoint_role_moid:
        module.fail_json(msg=f"EndPointRole '{role_name}' not found")
    group_api_body = {
        'Name': group_config['name'],
        'GroupDn': group_config['group_dn'],
        'EndPointRole': [endpoint_role_moid],
        'LdapPolicy': ldap_policy_moid
    }
    if group_config.get('domain'):
        group_api_body['Domain'] = group_config['domain']
    return group_api_body


def build_ldap_provider_api_body(provider_config, ldap_policy_moid):
    """
    Build LDAP provider API body.
    """
    vendor_map = {
        'openldap': 'OpenLDAP',
        'msad': 'MSAD'
    }
    provider_api_body = {
        'Server': provider_config['server'],
        'Port': provider_config.get('port', 389),
        'Vendor': vendor_map[provider_config.get('vendor', 'openldap')],
        'LdapPolicy': ldap_policy_moid
    }
    return provider_api_body


def main():
    ldap_group_options = dict(
        name=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        group_dn=dict(type='str'),
        domain=dict(type='str'),
        role=dict(type='str', choices=['admin', 'readonly', 'user'], default='admin')
    )
    ldap_provider_options = dict(
        server=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        port=dict(type='int', default=389),
        vendor=dict(type='str', choices=['openldap', 'msad'], default='openldap')
    )
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enable_ldap=dict(type='bool', default=True),
        base_dn=dict(type='str'),
        domain=dict(type='str'),
        timeout=dict(type='int', default=0),
        enable_encryption=dict(type='bool', default=False),
        bind_method=dict(type='str', choices=['logincredentials', 'anonymous', 'configuredcredentials'], default='logincredentials'),
        bind_dn=dict(type='str'),
        password=dict(type='str', no_log=True),
        filter=dict(type='str'),
        group_attribute=dict(type='str'),
        attribute=dict(type='str'),
        group_authorization=dict(type='bool', default=False),
        nested_group_search=dict(type='bool', default=False),
        nested_group_search_depth=dict(type='int', default=128),
        enable_dns=dict(type='bool', default=False),
        dns_source=dict(type='str', choices=['extracted', 'configured', 'configuredextracted'], default='extracted'),
        search_domain=dict(type='str'),
        search_forest=dict(type='str'),
        user_search_precedence=dict(type='str', choices=['localuserdb', 'ldapuserdb'], default='localuserdb'),
        ldap_groups=dict(type='list', elements='dict', options=ldap_group_options),
        ldap_providers=dict(type='list', elements='dict', options=ldap_provider_options)
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
    resource_path = '/iam/LdapPolicies'

    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    # Start propogating the api body for the main resource (Ldap Policy)
    if intersight.module.params['state'] == 'present':
        intersight.set_tags_and_description()
        intersight.api_body['Enabled'] = intersight.module.params['enable_ldap']

        bind_method_map = {
            'logincredentials': 'LoginCredentials',
            'anonymous': 'Anonymous',
            'configuredcredentials': 'ConfiguredCredentials'
        }

        base_properties = {
            'BaseDn': intersight.module.params['base_dn'],
            'Domain': intersight.module.params['domain'],
            'Timeout': intersight.module.params['timeout'],
            'EnableEncryption': intersight.module.params['enable_encryption'],
            'BindMethod': bind_method_map[intersight.module.params['bind_method']],
            'Filter': intersight.module.params['filter'],
            'GroupAttribute': intersight.module.params['group_attribute'],
            'Attribute': intersight.module.params['attribute'],
            'EnableGroupAuthorization': intersight.module.params['group_authorization'],
            'EnableNestedGroupSearch': intersight.module.params['nested_group_search']
        }

        if intersight.module.params['bind_method'] == 'configuredcredentials':
            base_properties['BindDn'] = intersight.module.params['bind_dn']
            base_properties['Password'] = intersight.module.params['password']

        if intersight.module.params['nested_group_search']:
            base_properties['NestedGroupSearchDepth'] = intersight.module.params['nested_group_search_depth']

        intersight.api_body['BaseProperties'] = base_properties
        intersight.api_body['EnableDns'] = intersight.module.params['enable_dns']
        if intersight.module.params['enable_dns']:
            dns_source_map = {
                'extracted': 'Extracted',
                'configured': 'Configured',
                'configuredextracted': 'ConfiguredExtracted'
            }
            dns_parameters = {
                'Source': dns_source_map[intersight.module.params['dns_source']]
            }
            if intersight.module.params['dns_source'] in ['configured', 'configuredextracted']:
                dns_parameters['SearchDomain'] = intersight.module.params['search_domain']
                dns_parameters['SearchForest'] = intersight.module.params['search_forest']

            intersight.api_body['DnsParameters'] = dns_parameters

        user_search_precedence_map = {
            'localuserdb': 'LocalUserDb',
            'ldapuserdb': 'LDAPUserDb'
        }
        intersight.api_body['UserSearchPrecedence'] = user_search_precedence_map[intersight.module.params['user_search_precedence']]

    intersight.configure_policy_or_profile(resource_path=resource_path)

    # Save the LDAP policy response
    ldap_policy_response = intersight.result['api_response']
    ldap_policy_moid = None

    if intersight.module.params['state'] == 'present' and ldap_policy_response:
        ldap_policy_moid = ldap_policy_response.get('Moid')

    # Process LDAP groups
    groups_response = []
    ldap_groups = intersight.module.params.get('ldap_groups') or []
    if intersight.module.params['state'] == 'present' and ldap_groups:
        for group_config in ldap_groups:
            group_state = group_config.get('state', 'present')
            if group_state == 'present':
                group_api_body = build_ldap_group_api_body(intersight, module, group_config, ldap_policy_moid)
                intersight.api_body = group_api_body

            resource_path = '/iam/LdapGroups'
            custom_filter = f"Name eq '{group_config['name']}' and LdapPolicy.Moid eq '{ldap_policy_moid}'"
            intersight.configure_secondary_resource(
                resource_path=resource_path,
                state=group_state,
                custom_filter=custom_filter
            )
            if group_state == 'present':
                groups_response.append(intersight.result['api_response'])

    # Process LDAP providers
    providers_response = []
    ldap_providers = intersight.module.params.get('ldap_providers') or []
    if intersight.module.params['state'] == 'present' and not intersight.module.params['enable_dns']:
        if ldap_providers:
            for provider_config in ldap_providers:
                provider_state = provider_config.get('state', 'present')
                if provider_state == 'present':
                    provider_api_body = build_ldap_provider_api_body(provider_config, ldap_policy_moid)
                    intersight.api_body = provider_api_body

                resource_path = '/iam/LdapProviders'
                custom_filter = f"Server eq '{provider_config['server']}' and LdapPolicy.Moid eq '{ldap_policy_moid}'"
                intersight.configure_secondary_resource(
                    resource_path=resource_path,
                    state=provider_state,
                    custom_filter=custom_filter
                )
                if provider_state == 'present':
                    providers_response.append(intersight.result['api_response'])

    if ldap_policy_response:
        ldap_policy_response['Groups'] = groups_response
        ldap_policy_response['Providers'] = providers_response
        intersight.result['api_response'] = ldap_policy_response
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
