#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2021, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  module: vault_login
  version_added: 2.2.0
  author:
    - Brian Scholer (@briantist)
  short_description: Perform a login operation against HashiCorp Vault
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:
    - Performs a login operation against a given path in HashiCorp Vault, returning the login response, including the token.
  seealso:
    - ref: community.hashi_vault.vault_login lookup <ansible_collections.community.hashi_vault.vault_login_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_login) lookup plugin.
    - ref: community.hashi_vault.vault_login_token filter <ansible_collections.community.hashi_vault.vault_login_token_filter>
      description: The official documentation for the C(community.hashi_vault.vault_login_token) filter plugin.
  extends_documentation_fragment:
    - community.hashi_vault.attributes
    - community.hashi_vault.attributes.action_group
    - community.hashi_vault.connection
    - community.hashi_vault.auth
  notes:
    - "A login is a write operation (creating a token persisted to storage), so this module always reports C(changed=True),
      except when used with C(token) auth, because no new token is created in that case. For the purposes of Ansible playbooks however,
      it may be more useful to set C(changed_when=false) if you're doing idempotency checks against the target system."
    - The C(none) auth method is not valid for this module because there is no response to return.
    - "With C(token) auth, no actual login is performed.
      Instead, the given token's additional information is returned in a structure that resembles what login responses look like."
    - "The C(token) auth method will only return full information if I(token_validate=True).
      If the token does not have the C(lookup-self) capability, this will fail. If I(token_validate=False), only the token value itself
      will be returned in the structure."
  attributes:
    check_mode:
      support: partial
      details:
        - In check mode, this module will not perform a login, and will instead return a basic structure with an empty token.
          However this may not be useful if the token is required for follow on tasks.
        - It may be better to use this module with C(check_mode=false) in order to have a valid token that can be used.
  options:
    token_validate:
      default: true
"""

EXAMPLES = """
- name: Login and use the resulting token
  community.hashi_vault.vault_login:
    url: https://vault:8201
    auth_method: userpass
    username: user
    password: '{{ passwd }}'
  register: login_data

- name: Retrieve an approle role ID (token via filter)
  community.hashi_vault.vault_read:
    url: https://vault:8201
    auth_method: token
    token: '{{ login_data | community.hashi_vault.vault_login_token }}'
    path: auth/approle/role/role-name/role-id
  register: approle_id

- name: Retrieve an approle role ID (token via direct dict access)
  community.hashi_vault.vault_read:
    url: https://vault:8201
    auth_method: token
    token: '{{ login_data.login.auth.client_token }}'
    path: auth/approle/role/role-name/role-id
  register: approle_id

# GCP auth
- name: Login with GCP auth
  community.hashi_vault.vault_login:
    auth_method: gcp
    role_id: myroleid
    jwt: myjwt
    url: https://vault:8200
  register: gcp_login

- name: Read a secret using the GCP login token
  community.hashi_vault.vault_read:
    url: https://vault:8200
    token: '{{ gcp_login.login.auth.client_token }}'
    path: secret/data/foo
"""

RETURN = """
login:
  description: The result of the login against the given auth method.
  returned: success
  type: dict
  contains:
    auth:
      description: The C(auth) member of the login response.
      returned: success
      type: dict
      contains:
        client_token:
          description: Contains the token provided by the login operation (or the input token when I(auth_method=token)).
          returned: success
          type: str
    data:
      description: The C(data) member of the login response.
      returned: success, when available
      type: dict
"""

import traceback

from ansible.module_utils.common.text.converters import to_text

from ...plugins.module_utils._hashi_vault_module import HashiVaultModule
from ...plugins.module_utils._hashi_vault_common import HashiVaultValueError

# we don't actually need to import hvac directly in this module
# because all of the hvac calls happen in module utils, but
# we would like to control the error message here for consistency.


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        # we override this from the shared argspec in order to turn off no_log
        # otherwise we would not be able to return the input token value
        token=dict(type='str', no_log=False, default=None),

        # we override this from the shared argspec because the default for
        # this module should be True, which differs from the rest of the
        # collection since 4.0.0.
        token_validate=dict(type='bool', default=True)
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    # a login is technically a write operation, using storage and resources
    changed = True
    auth_method = module.params.get('auth_method')

    if auth_method == 'none':
        module.fail_json(msg="The 'none' auth method is not valid for this module.")

    if auth_method == 'token':
        # with the token auth method, we don't actually perform a login operation
        # nor change the state of Vault; it's read-only (to lookup the token's info)
        changed = False

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)

    try:
        module.authenticator.validate()
        if module.check_mode:
            response = {'auth': {'client_token': None}}
        else:
            response = module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_text(e), exception=traceback.format_exc())

    module.exit_json(changed=changed, login=response)


def main():
    run_module()


if __name__ == '__main__':
    main()
