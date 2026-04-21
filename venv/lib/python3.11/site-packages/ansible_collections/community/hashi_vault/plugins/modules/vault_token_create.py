#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  module: vault_token_create
  version_added: 2.3.0
  author:
    - Brian Scholer (@briantist)
  short_description: Create a HashiCorp Vault token
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:
    - Creates a token in HashiCorp Vault, returning the response, including the token.
  seealso:
    - ref: community.hashi_vault.vault_token_create lookup <ansible_collections.community.hashi_vault.vault_token_create_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_token_create) lookup plugin.
    - module: community.hashi_vault.vault_login
    - ref: community.hashi_vault.vault_login lookup <ansible_collections.community.hashi_vault.vault_login_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_login) lookup plugin.
    - ref: community.hashi_vault.vault_login_token filter <ansible_collections.community.hashi_vault.vault_login_token_filter>
      description: The official documentation for the C(community.hashi_vault.vault_login_token) filter plugin.
  extends_documentation_fragment:
    - community.hashi_vault.attributes
    - community.hashi_vault.attributes.action_group
    - community.hashi_vault.connection
    - community.hashi_vault.auth
    - community.hashi_vault.token_create
    - community.hashi_vault.wrapping
  notes:
    - Token creation is a write operation (creating a token persisted to storage), so this module always reports C(changed=True).
    - For the purposes of Ansible playbooks however,
      it may be more useful to set I(changed_when=false) if you are doing idempotency checks against the target system.
  attributes:
    check_mode:
      support: partial
      details:
        - In check mode, this module will not create a token, and will instead return a basic structure with an empty token.
          However, this may not be useful if the token is required for follow on tasks.
        - It may be better to use this module with I(check_mode=false) in order to have a valid token that can be used.
  options: {}
"""

EXAMPLES = """
- name: Login via userpass and create a child token
  community.hashi_vault.vault_token_create:
    url: https://vault:8201
    auth_method: userpass
    username: user
    password: '{{ passwd }}'
  register: token_data

- name: Retrieve an approle role ID using the child token (token via filter)
  community.hashi_vault.vault_read:
    url: https://vault:8201
    auth_method: token
    token: '{{ token_data | community.hashi_vault.vault_login_token }}'
    path: auth/approle/role/role-name/role-id
  register: approle_id

- name: Retrieve an approle role ID using the child token (token via direct dict access)
  community.hashi_vault.vault_read:
    url: https://vault:8201
    auth_method: token
    token: '{{ token_data.login.auth.client_token }}'
    path: auth/approle/role/role-name/role-id
  register: approle_id

# implicitly uses token auth with a token from the environment
- name: Create an orphaned token with a short TTL
  community.hashi_vault.vault_token_create:
    url: https://vault:8201
    orphan: true
    ttl: 60s
  register: token_data

- name: Display the full response
  ansible.builtin.debug:
    var: token_data.login
"""

RETURN = """
login:
  description: The result of the token creation operation.
  returned: success
  type: dict
  sample:
    auth:
      client_token: s.rlwajI2bblHAWU7uPqZhLru3
    data: null
  contains:
    auth:
      description: The C(auth) member of the token response.
      returned: success
      type: dict
      contains:
        client_token:
          description: Contains the newly created token.
          returned: success
          type: str
    data:
      description: The C(data) member of the token response.
      returned: success, when available
      type: dict
"""

import traceback

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError


PASS_THRU_OPTION_NAMES = [
    'no_parent',
    'no_default_policy',
    'policies',
    'id',
    'role_name',
    'meta',
    'renewable',
    'ttl',
    'type',
    'explicit_max_ttl',
    'display_name',
    'num_uses',
    'period',
    'entity_alias',
    'wrap_ttl',
]


ORPHAN_OPTION_TRANSLATION = {
    'id': 'token_id',
    'role_name': 'role',
    'type': 'token_type',
}


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        orphan=dict(type='bool', default=False),
        no_parent=dict(type='bool'),
        no_default_policy=dict(type='bool'),
        policies=dict(type='list', elements='str'),
        id=dict(type='str'),
        role_name=dict(type='str'),
        meta=dict(type='dict'),
        renewable=dict(type='bool'),
        ttl=dict(type='str'),
        type=dict(type='str', choices=['batch', 'service']),
        explicit_max_ttl=dict(type='str'),
        display_name=dict(type='str'),
        num_uses=dict(type='int'),
        period=dict(type='str'),
        entity_alias=dict(type='str'),
        wrap_ttl=dict(type='str'),
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_text(e), exception=traceback.format_exc())

    pass_thru_options = module.adapter.get_filled_options(*PASS_THRU_OPTION_NAMES)

    orphan_options = pass_thru_options.copy()

    for key in pass_thru_options.keys():
        if key in ORPHAN_OPTION_TRANSLATION:
            orphan_options[ORPHAN_OPTION_TRANSLATION[key]] = orphan_options.pop(key)

    # token creation is a write operation, using storage and resources
    changed = True
    response = None

    if module.check_mode:
        module.exit_json(changed=changed, login={'auth': {'client_token': None}})

    if module.adapter.get_option('orphan'):
        try:
            try:
                # this method was added in hvac 1.0.0
                # See: https://github.com/hvac/hvac/pull/869
                response = client.auth.token.create_orphan(**orphan_options)
            except AttributeError:
                # this method was removed in hvac 1.0.0
                # See: https://github.com/hvac/hvac/issues/758
                response = client.create_token(orphan=True, **orphan_options)
        except Exception as e:
            module.fail_json(msg=to_text(e), exception=traceback.format_exc())
    else:
        try:
            response = client.auth.token.create(**pass_thru_options)
        except Exception as e:
            module.fail_json(msg=to_text(e), exception=traceback.format_exc())

    module.exit_json(changed=changed, login=response)


def main():
    run_module()


if __name__ == '__main__':
    main()
