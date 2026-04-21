#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2019 Christoffer Reijer (Basalt AB)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: auth_source_ldap
version_added: 1.0.0
short_description: Manage LDAP Authentication Sources
description:
  - Create, update, and delete LDAP authentication sources
author:
  - "Christoffer Reijer (@ephracis) Basalt AB"
options:
  name:
    description: The name of the LDAP authentication source
    required: true
    type: str
  host:
    description: The hostname of the LDAP server
    required: true
    type: str
  port:
    description: The port number of the LDAP server
    required: false
    type: int
    default: 389
  account:
    description: Account name to use when accessing the LDAP server.
    required: false
    type: str
  account_password:
    description:
      - Account password to use when accessing the LDAP server.
      - Required when using I(onthefly_register).
      - When this parameter is set, the module will not be idempotent.
    required: false
    type: str
  base_dn:
    description: The base DN to use when searching.
    required: false
    type: str
  attr_login:
    description:
      - Attribute containing login ID.
      - Required when using I(onthefly_register).
    required: false
    type: str
  attr_firstname:
    description:
      - Attribute containing first name.
      - Required when using I(onthefly_register).
    required: false
    type: str
  attr_lastname:
    description:
      - Attribute containing last name.
      - Required when using I(onthefly_register).
    required: false
    type: str
  attr_mail:
    description:
      - Attribute containing email address.
      - Required when using I(onthefly_register).
    required: false
    type: str
  attr_photo:
    description: Attribute containing user photo
    required: false
    type: str
  onthefly_register:
    description: Whether or not to register users on the fly.
    required: false
    type: bool
  usergroup_sync:
    description: Whether or not to sync external user groups on login
    required: false
    type: bool
  tls:
    description: Whether or not to use TLS when contacting the LDAP server.
    required: false
    type: bool
  groups_base:
    description: Base DN where groups reside.
    required: false
    type: str
  use_netgroups:
    description:
      - Whether to use NIS netgroups instead of posix groups, not valid for I(server_type=active_directory)
      - "Deprecated: The I(use_netgroups) parameter is deprecated with Foreman 3.16
         in favor of I(ldap_group_membership) and will be removed in a future release."
    required: false
    type: bool
  ldap_group_membership:
    description: Which group membership method to use, not valid for I(server_type=active_directory). Option I(rfc4519) is valid only for I(server_type=posix).
    required: false
    type: str
    choices: ["posix", "nis_netgroups", "rfc4519"]
  server_type:
    description: Type of the LDAP server
    required: false
    choices: ["free_ipa", "active_directory", "posix"]
    type: str
  ldap_filter:
    description: Filter to apply to LDAP searches
    required: false
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state
  - theforeman.foreman.foreman.taxonomy
'''

EXAMPLES = '''
- name: Simple FreeIPA authentication source
  theforeman.foreman.auth_source_ldap:
    name: "Example LDAP"
    host: "ldap.example.org"
    server_url: "https://foreman.example.com"
    locations:
      - "Uppsala"
    organizations:
      - "Sweden"
    username: "admin"
    password: "changeme"
    state: present

- name: FreeIPA with automatic registration
  theforeman.foreman.auth_source_ldap:
    name: "Example LDAP"
    host: "ldap.example.org"
    onthefly_register: true
    account: uid=ansible,cn=sysaccounts,cn=etc,dc=example,dc=com
    account_password: secret
    base_dn: dc=example,dc=com
    groups_base: cn=groups,cn=accounts, dc=example,dc=com
    server_type: free_ipa
    attr_login: uid
    attr_firstname: givenName
    attr_lastname: sn
    attr_mail: mail
    attr_photo: jpegPhoto
    server_url: "https://foreman.example.com"
    username: "admin"
    password: "changeme"
    state: present

- name: Active Directory with automatic registration
  theforeman.foreman.auth_source_ldap:
    name: "Example AD"
    host: "ad.example.org"
    onthefly_register: true
    account: EXAMPLE\\ansible
    account_password: secret
    base_dn: cn=Users,dc=example,dc=com
    groups_base: cn=Users,dc=example,dc=com
    server_type: active_directory
    attr_login: sAMAccountName
    attr_firstname: givenName
    attr_lastname: sn
    attr_mail: mail
    ldap_filter: (memberOf=CN=Domain Users,CN=Users,DC=example,DC=com)
    server_url: "https://foreman.example.com"
    username: "admin"
    password: "changeme"
    state: present
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    auth_source_ldaps:
      description: List of auth sources for LDAP.
      type: list
      elements: dict
'''


from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanTaxonomicEntityAnsibleModule


class ForemanAuthSourceLdapModule(ForemanTaxonomicEntityAnsibleModule):
    pass


def main():
    module = ForemanAuthSourceLdapModule(
        foreman_spec=dict(
            name=dict(required=True),
            host=dict(required=True),
            port=dict(type='int', default=389),
            account=dict(),
            account_password=dict(no_log=True),
            base_dn=dict(),
            attr_login=dict(),
            attr_firstname=dict(),
            attr_lastname=dict(),
            attr_mail=dict(),
            attr_photo=dict(),
            onthefly_register=dict(type='bool'),
            usergroup_sync=dict(type='bool'),
            tls=dict(type='bool'),
            groups_base=dict(),
            server_type=dict(choices=["free_ipa", "active_directory", "posix"]),
            ldap_filter=dict(),
            use_netgroups=dict(type='bool'),
            ldap_group_membership=dict(choices=["posix", "nis_netgroups", "rfc4519"]),
        ),
        required_if=[['onthefly_register', True, ['attr_login', 'attr_firstname', 'attr_lastname', 'attr_mail']]],
    )

    # additional parameter checks
    use_netgroups = module.foreman_params.get('use_netgroups')
    server_type = module.foreman_params.get('server_type', 'posix')

    if server_type == 'active_directory' and ('ldap_group_membership' in module.foreman_params or 'use_netgroups' in module.foreman_params):
        module.fail_json(msg='ldap_group_membership and use_netgroup params cannot be used when server_type=active_directory')

    if 'ldap_group_membership' in module.foreman_params and module.foreman_params['ldap_group_membership'] == 'rfc4519' and server_type != 'posix':
        module.fail_json(msg=f'ldap_group_membership=rfc4519 cannot be used when server_type={server_type}')

    with module.api_connection():
        _supported_params, unsupported_params = module.foremanapi.validate_payload('auth_source_ldaps', 'create', module.foreman_params)
        # Priority: ldap_group_membership > use_netgroups > use_netgroups derived from ldap_group_membership
        if 'ldap_group_membership' in unsupported_params:
            ldap_group_membership = module.foreman_params.pop('ldap_group_membership')
            if use_netgroups is None:
                derived = ldap_group_membership == 'nis_netgroups'
                module.warn(
                    f"Server does not support ldap_group_membership parameter and no use_netgroups value was provided, using derived use_netgroups={derived}"
                )
                module.foreman_params['use_netgroups'] = derived

        module.run()


if __name__ == '__main__':
    main()
