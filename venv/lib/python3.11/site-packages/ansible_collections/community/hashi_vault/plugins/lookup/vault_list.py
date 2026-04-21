# (c) 2023, Tom Kivlin (@tomkivlin)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  name: vault_list
  version_added: 4.1.0
  author:
    - Tom Kivlin (@tomkivlin)
  short_description: Perform a list operation against HashiCorp Vault
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:
    - Performs a generic list operation against a given path in HashiCorp Vault.
  seealso:
    - module: community.hashi_vault.vault_list
  extends_documentation_fragment:
    - community.hashi_vault.connection
    - community.hashi_vault.connection.plugins
    - community.hashi_vault.auth
    - community.hashi_vault.auth.plugins
  options:
    _terms:
      description: Vault path(s) to be listed.
      type: str
      required: true
"""

EXAMPLES = """
- name: List all secrets at a path
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.vault_list', 'secret/metadata', url='https://vault:8201') }}"
    # For kv2, the path needs to follow the pattern 'mount_point/metadata' or 'mount_point/metadata/path' to list all secrets in that path

- name: List access policies
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.vault_list', 'sys/policies/acl', url='https://vault:8201') }}"

- name: Perform multiple list operations with a single Vault login
  vars:
    paths:
      - secret/metadata
      - sys/policies/acl
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.vault_list', *paths, auth_method='userpass', username=user, password=pwd) }}"

- name: Perform multiple list operations with a single Vault login in a loop
  vars:
    paths:
      - secret/metadata
      - sys/policies/acl
  ansible.builtin.debug:
    msg: '{{ item }}'
  loop: "{{ query('community.hashi_vault.vault_list', *paths, auth_method='userpass', username=user, password=pwd) }}"

- name: Perform list operations with a single Vault login in a loop (via with_)
  vars:
    ansible_hashi_vault_auth_method: userpass
    ansible_hashi_vault_username: '{{ user }}'
    ansible_hashi_vault_password: '{{ pwd }}'
  ansible.builtin.debug:
    msg: '{{ item }}'
  with_community.hashi_vault.vault_list:
    - secret/metadata
    - sys/policies/acl

- name: Create fact consisting of list of dictionaries each with secret name (e.g. username) and value of a key (e.g. 'password') within that secret
  ansible.builtin.set_fact:
    credentials: >-
      {{
        credentials
        | default([]) + [
          {
            'username': item,
            'password': lookup('community.hashi_vault.vault_kv2_get', item, engine_mount_point='vpn-users').secret.password
          }
        ]
      }}
  loop: "{{ query('community.hashi_vault.vault_list', 'vpn-users/metadata')[0].data['keys'] }}"
  no_log: true

- ansible.builtin.debug:
    msg: "{{ credentials }}"

- name: Create the same as above without looping, and only 2 logins
  vars:
    secret_names: >-
      {{
        query('community.hashi_vault.vault_list', 'vpn-users/metadata')
        | map(attribute='data')
        | map(attribute='keys')
        | flatten
      }}
    secret_values: >-
      {{
        lookup('community.hashi_vault.vault_kv2_get', *secret_names, engine_mount_point='vpn-users')
        | map(attribute='secret')
        | map(attribute='password')
        | flatten
      }}
    credentials_dict: "{{ dict(secret_names | zip(secret_values)) }}"
  ansible.builtin.set_fact:
    credentials_dict: "{{ credentials_dict }}"
    credentials_list: "{{ credentials_dict | dict2items(key_name='username', value_name='password') }}"
  no_log: true

- ansible.builtin.debug:
    msg:
      - "Dictionary: {{ credentials_dict }}"
      - "List: {{ credentials_list }}"

- name: List all userpass users and output the token policies for each user
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.vault_read', 'auth/userpass/users/' + item).data.token_policies }}"
  loop: "{{ query('community.hashi_vault.vault_list', 'auth/userpass/users')[0].data['keys'] }}"
"""

RETURN = """
_raw:
  description:
    - The raw result of the read against the given path.
  type: list
  elements: dict
"""

from ansible.errors import AnsibleError
from ansible.utils.display import Display

from ansible_collections.community.hashi_vault.plugins.plugin_utils._hashi_vault_lookup_base import HashiVaultLookupBase
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError

display = Display()


class LookupModule(HashiVaultLookupBase):
    def run(self, terms, variables=None, **kwargs):
        ret = []

        self.set_options(direct=kwargs, var_options=variables)
        # TODO: remove process_deprecations() if backported fix is available (see method definition)
        self.process_deprecations()

        self.connection_options.process_connection_options()
        client_args = self.connection_options.get_hvac_connection_options()
        client = self.helper.get_vault_client(**client_args)
        hvac_exceptions = self.helper.get_hvac().exceptions

        try:
            self.authenticator.validate()
            self.authenticator.authenticate(client)
        except (NotImplementedError, HashiVaultValueError) as e:
            raise AnsibleError(e)

        for term in terms:
            try:
                data = client.list(term)
            except hvac_exceptions.Forbidden:
                raise AnsibleError("Forbidden: Permission Denied to path '%s'." % term)

            if data is None:
                raise AnsibleError("The path '%s' doesn't seem to exist." % term)

            ret.append(data)

        return ret
