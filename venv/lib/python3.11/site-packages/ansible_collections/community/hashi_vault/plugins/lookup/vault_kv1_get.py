# (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
name: vault_kv1_get
version_added: 2.5.0
author:
  - Brian Scholer (@briantist)
short_description: Get a secret from HashiCorp Vault's KV version 1 secret store
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Gets a secret from HashiCorp Vault's KV version 1 secret store.
seealso:
  - module: community.hashi_vault.vault_kv1_get
  - ref: community.hashi_vault.vault_kv2_get lookup <ansible_collections.community.hashi_vault.vault_kv2_get_lookup>
    description: The official documentation for the C(community.hashi_vault.vault_kv2_get) lookup plugin.
  - module: community.hashi_vault.vault_kv2_get
  - ref: community.hashi_vault Lookup Guide <ansible_collections.community.hashi_vault.docsite.lookup_guide>
    description: Guidance on using lookups in C(community.hashi_vault).
  - name: KV1 Secrets Engine
    description: Documentation for the Vault KV secrets engine, version 1.
    link: https://www.vaultproject.io/docs/secrets/kv/kv-v1
extends_documentation_fragment:
  - community.hashi_vault.connection
  - community.hashi_vault.connection.plugins
  - community.hashi_vault.auth
  - community.hashi_vault.auth.plugins
  - community.hashi_vault.engine_mount
  - community.hashi_vault.engine_mount.plugins
options:
  _terms:
    description:
      - Vault KV path(s) to be read.
      - These are relative to the I(engine_mount_point), so the mount path should not be included.
    type: str
    required: True
  engine_mount_point:
    default: kv
'''

EXAMPLES = r'''
- name: Read a kv1 secret with the default mount point
  ansible.builtin.set_fact:
    response: "{{ lookup('community.hashi_vault.vault_kv1_get', 'hello', url='https://vault:8201') }}"
  # equivalent API path is kv/hello

- name: Display the results
  ansible.builtin.debug:
    msg:
      - "Secret: {{ response.secret }}"
      - "Data: {{ response.data }} (same as secret in kv1)"
      - "Metadata: {{ response.metadata }} (response info in kv1)"
      - "Full response: {{ response.raw }}"
      - "Value of key 'password' in the secret: {{ response.secret.password }}"

- name: Read a kv1 secret with a different mount point
  ansible.builtin.set_fact:
    response: "{{ lookup('community.hashi_vault.vault_kv1_get', 'hello', engine_mount_point='custom/kv1/mount', url='https://vault:8201') }}"
  # equivalent API path is custom/kv1/mount/hello

- name: Display the results
  ansible.builtin.debug:
    msg:
      - "Secret: {{ response.secret }}"
      - "Data: {{ response.data }} (same as secret in kv1)"
      - "Metadata: {{ response.metadata }} (response info in kv1)"
      - "Full response: {{ response.raw }}"
      - "Value of key 'password' in the secret: {{ response.secret.password }}"

- name: Perform multiple kv1 reads with a single Vault login, showing the secrets
  vars:
    paths:
      - hello
      - my-secret/one
      - my-secret/two
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.vault_kv1_get', *paths, auth_method='userpass', username=user, password=pwd)['secret'] }}"

- name: Perform multiple kv1 reads with a single Vault login in a loop
  vars:
    paths:
      - hello
      - my-secret/one
      - my-secret/two
  ansible.builtin.debug:
    msg: '{{ item }}'
  loop: "{{ query('community.hashi_vault.vault_kv1_get', *paths, auth_method='userpass', username=user, password=pwd) }}"

- name: Perform multiple kv1 reads with a single Vault login in a loop (via with_), display values only
  vars:
    ansible_hashi_vault_auth_method: userpass
    ansible_hashi_vault_username: '{{ user }}'
    ansible_hashi_vault_password: '{{ pwd }}'
  ansible.builtin.debug:
    msg: '{{ item.values() | list }}'
  with_community.hashi_vault.vault_kv1_get:
    - hello
    - my-secret/one
    - my-secret/two
'''

RETURN = r'''
_raw:
  description:
    - The result of the read(s) against the given path(s).
  type: list
  elements: dict
  contains:
    raw:
      description: The raw result of the read against the given path.
      returned: success
      type: dict
      sample:
        auth: null
        data:
          Key1: value1
          Key2: value2
        lease_duration: 2764800
        lease_id: ""
        renewable: false
        request_id: e99f145f-f02a-7073-1229-e3f191057a70
        warnings: null
        wrap_info: null
    data:
      description: The C(data) field of raw result. This can also be accessed via C(raw.data).
      returned: success
      type: dict
      sample:
        Key1: value1
        Key2: value2
    secret:
      description: The C(data) field of the raw result. This is identical to C(data) in the return values.
      returned: success
      type: dict
      sample:
        Key1: value1
        Key2: value2
    metadata:
      description: This is a synthetic result. It is the same as C(raw) with C(data) removed.
      returned: success
      type: dict
      sample:
        auth: null
        lease_duration: 2764800
        lease_id: ""
        renewable: false
        request_id: e99f145f-f02a-7073-1229-e3f191057a70
        warnings: null
        wrap_info: null
'''

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

        engine_mount_point = self._options_adapter.get_option('engine_mount_point')

        try:
            self.authenticator.validate()
            self.authenticator.authenticate(client)
        except (NotImplementedError, HashiVaultValueError) as e:
            raise AnsibleError(e)

        for term in terms:
            try:
                raw = client.secrets.kv.v1.read_secret(path=term, mount_point=engine_mount_point)
            except hvac_exceptions.Forbidden as e:
                raise AnsibleError("Forbidden: Permission Denied to path ['%s']." % term) from e
            except hvac_exceptions.InvalidPath as e:
                if 'Invalid path for a versioned K/V secrets engine' in str(e):
                    msg = "Invalid path for a versioned K/V secrets engine ['%s']. If this is a KV version 2 path, use community.hashi_vault.vault_kv2_get."
                else:
                    msg = "Invalid or missing path ['%s']."

                raise AnsibleError(msg % (term,)) from e

            metadata = raw.copy()
            data = metadata.pop('data')

            ret.append(dict(raw=raw, data=data, secret=data, metadata=metadata))

        return ret
