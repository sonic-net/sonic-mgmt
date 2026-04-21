# (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  name: vault_token_create
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
    - module: community.hashi_vault.vault_token_create
    - ref: community.hashi_vault.vault_login lookup <ansible_collections.community.hashi_vault.vault_login_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_login) lookup plugin.
    - module: community.hashi_vault.vault_login
    - ref: community.hashi_vault.vault_login_token filter <ansible_collections.community.hashi_vault.vault_login_token_filter>
      description: The official documentation for the C(community.hashi_vault.vault_login_token) filter plugin.
  notes:
    - Token creation is a write operation (creating a token persisted to storage), so this module always reports C(changed=True).
    - For the purposes of Ansible playbooks however,
      it may be more useful to set I(changed_when=false) if you are doing idempotency checks against the target system.
    - In check mode, this module will not create a token, and will instead return a basic structure with an empty token.
      However, this may not be useful if the token is required for follow on tasks.
      It may be better to use this module with I(check_mode=false) in order to have a valid token that can be used.
  extends_documentation_fragment:
    - community.hashi_vault.connection
    - community.hashi_vault.connection.plugins
    - community.hashi_vault.auth
    - community.hashi_vault.auth.plugins
    - community.hashi_vault.token_create
    - community.hashi_vault.wrapping
    - community.hashi_vault.wrapping.plugins
  options:
    _terms:
      description: This is unused and any terms supplied will be ignored.
      type: str
      required: false
"""

EXAMPLES = """
- name: Login via userpass and create a child token
  ansible.builtin.set_fact:
    token_data: "{{ lookup('community.hashi_vault.vault_token_create', url='https://vault', auth_method='userpass', username=user, password=passwd) }}"

- name: Retrieve an approle role ID using the child token (token via filter)
  community.hashi_vault.vault_read:
    url: https://vault:8201
    auth_method: token
    token: '{{ token_data | community.hashi_vault.vault_login_token }}'
    path: auth/approle/role/role-name/role-id
  register: approle_id

- name: Retrieve an approle role ID (token via direct dict access)
  community.hashi_vault.vault_read:
    url: https://vault:8201
    auth_method: token
    token: '{{ token_data.auth.client_token }}'
    path: auth/approle/role/role-name/role-id
  register: approle_id

# implicitly uses url & token auth with a token from the environment
- name: Create an orphaned token with a short TTL and display the full response
  ansible.builtin.debug:
    var: lookup('community.hashi_vault.vault_token_create', orphan=True, ttl='60s')
"""

RETURN = """
_raw:
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

from ansible.errors import AnsibleError
from ansible.utils.display import Display

from ...plugins.plugin_utils._hashi_vault_lookup_base import HashiVaultLookupBase
from ...plugins.module_utils._hashi_vault_common import HashiVaultValueError

display = Display()


class LookupModule(HashiVaultLookupBase):
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

    def run(self, terms, variables=None, **kwargs):
        self.set_options(direct=kwargs, var_options=variables)
        # TODO: remove process_deprecations() if backported fix is available (see method definition)
        self.process_deprecations()

        self.connection_options.process_connection_options()
        client_args = self.connection_options.get_hvac_connection_options()
        client = self.helper.get_vault_client(**client_args)

        if len(terms) != 0:
            display.warning("Supplied term strings will be ignored. This lookup does not use term strings.")

        try:
            self.authenticator.validate()
            self.authenticator.authenticate(client)
        except (NotImplementedError, HashiVaultValueError) as e:
            raise AnsibleError(e)

        pass_thru_options = self._options_adapter.get_filled_options(*self.PASS_THRU_OPTION_NAMES)

        orphan_options = pass_thru_options.copy()

        for key in pass_thru_options.keys():
            if key in self.ORPHAN_OPTION_TRANSLATION:
                orphan_options[self.ORPHAN_OPTION_TRANSLATION[key]] = orphan_options.pop(key)

        response = None

        if self.get_option('orphan'):
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
                raise AnsibleError(e)
        else:
            try:
                response = client.auth.token.create(**pass_thru_options)
            except Exception as e:
                raise AnsibleError(e)

        return [response]
