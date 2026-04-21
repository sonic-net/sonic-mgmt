# (c) 2021, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  name: vault_login
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
    - module: community.hashi_vault.vault_login
    - ref: community.hashi_vault.vault_login_token filter <ansible_collections.community.hashi_vault.vault_login_token_filter>
      description: The official documentation for the C(community.hashi_vault.vault_login_token) filter plugin.
  notes:
    - This lookup does not use the term string and will not work correctly in loops. Only a single response will be returned.
    - "A login is a write operation (creating a token persisted to storage), so this module always reports C(changed=True),
      except when used with C(token) auth, because no new token is created in that case. For the purposes of Ansible playbooks however,
      it may be more useful to set C(changed_when=false) if you're doing idempotency checks against the target system."
    - The C(none) auth method is not valid for this plugin because there is no response to return.
    - "With C(token) auth, no actual login is performed.
      Instead, the given token's additional information is returned in a structure that resembles what login responses look like."
    - "The C(token) auth method will only return full information if I(token_validate=True).
      If the token does not have the C(lookup-self) capability, this will fail. If I(token_validate=False), only the token value itself
      will be returned in the structure."
  extends_documentation_fragment:
    - community.hashi_vault.connection
    - community.hashi_vault.connection.plugins
    - community.hashi_vault.auth
    - community.hashi_vault.auth.plugins
  options:
    _terms:
      description: This is unused and any terms supplied will be ignored.
      type: str
      required: false
    token_validate:
      default: true
"""

EXAMPLES = """
- name: Set a fact with a lookup result
  set_fact:
    login_data: "{{ lookup('community.hashi_vault.vault_login', url='https://vault', auth_method='userpass', username=user, password=pwd) }}"

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
    token: '{{ login_data.auth.client_token }}'
    path: auth/approle/role/role-name/role-id
  register: approle_id

- name: Login with GCP auth
  set_fact:
    gcp_login: "{{ lookup('community.hashi_vault.vault_login', auth_method='gcp', role_id='myroleid', jwt='myjwt', url='https://vault:8200') }}"

- name: Read a secret using the GCP login token
  community.hashi_vault.vault_read:
    url: https://vault:8200
    token: '{{ gcp_login.auth.client_token }}'
    path: secret/data/foo

"""

RETURN = """
_raw:
  description:
    - The result of the login with the given auth method.
  type: list
  elements: dict
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

from ansible.errors import AnsibleError
from ansible.utils.display import Display

from ...plugins.plugin_utils._hashi_vault_lookup_base import HashiVaultLookupBase
from ...plugins.module_utils._hashi_vault_common import HashiVaultValueError

display = Display()


class LookupModule(HashiVaultLookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(direct=kwargs, var_options=variables)
        # TODO: remove process_deprecations() if backported fix is available (see method definition)
        self.process_deprecations()

        if self.get_option('auth_method') == 'none':
            raise AnsibleError("The 'none' auth method is not valid for this lookup.")

        self.connection_options.process_connection_options()
        client_args = self.connection_options.get_hvac_connection_options()
        client = self.helper.get_vault_client(**client_args)

        if len(terms) != 0:
            display.warning("Supplied term strings will be ignored. This lookup does not use term strings.")

        try:
            self.authenticator.validate()
            response = self.authenticator.authenticate(client)
        except (NotImplementedError, HashiVaultValueError) as e:
            raise AnsibleError(e)

        return [response]
