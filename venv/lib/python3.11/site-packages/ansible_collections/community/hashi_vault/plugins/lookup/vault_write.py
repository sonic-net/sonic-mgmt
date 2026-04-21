# (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  name: vault_write
  version_added: 2.4.0
  author:
    - Brian Scholer (@briantist)
  short_description: Perform a write operation against HashiCorp Vault
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:
    - Performs a generic write operation against a given path in HashiCorp Vault, returning any output.
  seealso:
    - module: community.hashi_vault.vault_write
    - module: community.hashi_vault.vault_kv2_write
    - ref: community.hashi_vault.vault_read lookup <ansible_collections.community.hashi_vault.vault_read_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_read) lookup plugin.
    - module: community.hashi_vault.vault_read
    - ref: community.hashi_vault Lookup Guide <ansible_collections.community.hashi_vault.docsite.lookup_guide>
      description: Guidance on using lookups in C(community.hashi_vault).
  notes:
    - C(vault_write) is a generic plugin to do operations that do not yet have a dedicated plugin. Where a specific plugin exists, that should be used instead.
    - In the vast majority of cases, it will be better to do writes as a task, with the M(community.hashi_vault.vault_write) module.
    - The lookup can be used in cases where you need a value directly in templating, but there is risk of executing the write many times unintentionally.
    - The lookup is best used for endpoints that directly manipulate the input data and return a value, while not changing state in Vault.
    - See the R(Lookup Guide,ansible_collections.community.hashi_vault.docsite.lookup_guide) for more information.
  extends_documentation_fragment:
    - community.hashi_vault.connection
    - community.hashi_vault.connection.plugins
    - community.hashi_vault.auth
    - community.hashi_vault.auth.plugins
    - community.hashi_vault.wrapping
    - community.hashi_vault.wrapping.plugins
  options:
    _terms:
      description: Vault path(s) to be written to.
      type: str
      required: true
    data:
      description:
        - A dictionary to be serialized to JSON and then sent as the request body.
        - If the dictionary contains keys named C(path) or C(wrap_ttl), the call will fail with C(hvac<1.2).
      type: dict
      required: false
      default: {}
"""

EXAMPLES = """
# These examples show some uses that might work well as a lookup.
# For most uses, the vault_write module should be used.

- name: Retrieve and display random data
  vars:
    data:
      format: hex
    num_bytes: 64
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.vault_write', 'sys/tools/random/' ~ num_bytes, data=data) }}"

- name: Hash some data and display the hash
  vars:
    input: |
      Lorem ipsum dolor sit amet, consectetur adipiscing elit.
      Pellentesque posuere dui a ipsum dapibus, et placerat nibh bibendum.
    data:
      input: '{{ input | b64encode }}'
    hash_algo: sha2-256
  ansible.builtin.debug:
    msg: "The hash is {{ lookup('community.hashi_vault.vault_write', 'sys/tools/hash/' ~ hash_algo, data=data) }}"


# In this next example, the Ansible controller's token does not have permission to read the secrets we need.
# It does have permission to generate new secret IDs for an approle which has permission to read the secrets,
# however the approle is configured to:
# 1) allow a maximum of 1 use per secret ID
# 2) restrict the IPs allowed to use login using the approle to those of the remote hosts
#
# Normally, the fact that a new secret ID would be generated on every loop iteration would not be desirable,
# but here it's quite convenient.

- name: Retrieve secrets from the remote host with one-time-use approle creds
  vars:
    role_id: "{{ lookup('community.hashi_vault.vault_read', 'auth/approle/role/role-name/role-id') }}"
    secret_id: "{{ lookup('community.hashi_vault.vault_write', 'auth/approle/role/role-name/secret-id') }}"
  community.hashi_vault.vault_read:
    auth_method: approle
    role_id: '{{ role_id }}'
    secret_id: '{{ secret_id }}'
    path: '{{ item }}'
  register: secret_data
  loop:
    - secret/data/secret1
    - secret/data/app/deploy-key
    - secret/data/access-codes/self-destruct


# This time we have a secret values on the controller, and we need to run a command the remote host,
# that is expecting to a use single-use token as input, so we need to use wrapping to send the data.

- name: Run a command that needs wrapped secrets
  vars:
    secrets:
      secret1: '{{ my_secret_1 }}'
      secret2: '{{ second_secret }}'
    wrapped: "{{ lookup('community.hashi_vault.vault_write', 'sys/wrapping/wrap', data=secrets) }}"
  ansible.builtin.command: 'vault unwrap {{ wrapped }}'
"""

RETURN = """
_raw:
  description: The raw result of the write against the given path.
  type: list
  elements: dict
"""

from ansible.errors import AnsibleError
from ansible.utils.display import Display

from ..plugin_utils._hashi_vault_lookup_base import HashiVaultLookupBase
from ..module_utils._hashi_vault_common import HashiVaultValueError

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

        data = self._options_adapter.get_option('data')
        wrap_ttl = self._options_adapter.get_option_default('wrap_ttl')

        try:
            self.authenticator.validate()
            self.authenticator.authenticate(client)
        except (NotImplementedError, HashiVaultValueError) as e:
            raise AnsibleError(e) from e

        for term in terms:
            try:
                try:
                    # TODO: write_data will eventually turn back into write
                    # see: https://github.com/hvac/hvac/issues/1034
                    response = client.write_data(path=term, wrap_ttl=wrap_ttl, data=data)
                except AttributeError as e:
                    # https://github.com/ansible-collections/community.hashi_vault/issues/389
                    if "path" in data or "wrap_ttl" in data:
                        raise AnsibleError("To use 'path' or 'wrap_ttl' as data keys, use hvac >= 1.2") from e
                    else:
                        response = client.write(path=term, wrap_ttl=wrap_ttl, **data)
            except hvac_exceptions.Forbidden as e:
                raise AnsibleError("Forbidden: Permission Denied to path '%s'." % term) from e
            except hvac_exceptions.InvalidPath as e:
                raise AnsibleError("The path '%s' doesn't seem to exist." % term) from e
            except hvac_exceptions.InternalServerError as e:
                raise AnsibleError("Internal Server Error: %s" % str(e)) from e

            # https://github.com/hvac/hvac/issues/797
            # HVAC returns a raw response object when the body is not JSON.
            # That includes 204 responses, which are successful with no body.
            # So we will try to detect that and a act accordingly.
            # A better way may be to implement our own adapter for this
            # collection, but it's a little premature to do that.
            if hasattr(response, 'json') and callable(response.json):
                if response.status_code == 204:
                    output = {}
                else:
                    display.warning('Vault returned status code %i and an unparsable body.' % response.status_code)
                    output = response.content
            else:
                output = response

            ret.append(output)

        return ret
