# (c) 2020, Brian Scholer (@briantist)
# (c) 2015, Julie Davila (@juliedavila) <julie(at)davila.io>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  name: hashi_vault
  author:
    - Julie Davila (@juliedavila) <julie(at)davila.io>
    - Brian Scholer (@briantist)
  short_description: Retrieve secrets from HashiCorp's Vault
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:
    - Retrieve secrets from HashiCorp's Vault.
    - Consider R(migrating to other plugins in the collection,ansible_collections.community.hashi_vault.docsite.migration_hashi_vault_lookup).
  seealso:
    - ref: community.hashi_vault.hashi_vault Migration Guide <ansible_collections.community.hashi_vault.docsite.migration_hashi_vault_lookup>
      description: Migrating from the C(hashi_vault) lookup.
    - ref: About the community.hashi_vault.hashi_vault lookup <ansible_collections.community.hashi_vault.docsite.about_hashi_vault_lookup>
      description: The past, present, and future of the C(hashi_vault) lookup.
    - ref: community.hashi_vault.vault_read lookup <ansible_collections.community.hashi_vault.vault_read_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_read) lookup plugin.
    - module: community.hashi_vault.vault_read
    - ref: community.hashi_vault.vault_kv2_get lookup <ansible_collections.community.hashi_vault.vault_kv2_get_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_kv2_get) lookup plugin.
    - module: community.hashi_vault.vault_kv2_get
    - ref: community.hashi_vault.vault_kv1_get lookup <ansible_collections.community.hashi_vault.vault_kv1_get_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_kv1_get) lookup plugin.
    - module: community.hashi_vault.vault_kv1_get
    - ref: community.hashi_vault Lookup Guide <ansible_collections.community.hashi_vault.docsite.lookup_guide>
      description: Guidance on using lookups in C(community.hashi_vault).
  notes:
    - Due to a current limitation in the HVAC library there won't necessarily be an error if a bad endpoint is specified.
    - As of community.hashi_vault 0.1.0, only the latest version of a secret is returned when specifying a KV v2 path.
    - As of community.hashi_vault 0.1.0, all options can be supplied via term string (space delimited key=value pairs) or by parameters (see examples).
    - As of community.hashi_vault 0.1.0, when I(secret) is the first option in the term string, C(secret=) is not required (see examples).
  extends_documentation_fragment:
    - community.hashi_vault.connection
    - community.hashi_vault.connection.plugins
    - community.hashi_vault.auth
    - community.hashi_vault.auth.plugins
  options:
    secret:
      description: Vault path to the secret being requested in the format C(path[:field]).
      required: True
    return_format:
      description:
        - Controls how multiple key/value pairs in a path are treated on return.
        - C(dict) returns a single dict containing the key/value pairs.
        - C(values) returns a list of all the values only. Use when you don't care about the keys.
        - C(raw) returns the actual API result (deserialized), which includes metadata and may have the data nested in other keys.
      choices:
        - dict
        - values
        - raw
      default: dict
      aliases: [ as ]
"""

EXAMPLES = """
- ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/hello:value token=c975b780-d1be-8016-866b-01d0f9b688a5 url=http://myvault:8200') }}"

- name: Return all secrets from a path
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/hello token=c975b780-d1be-8016-866b-01d0f9b688a5 url=http://myvault:8200') }}"

- name: Vault that requires authentication via LDAP
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/hello:value auth_method=ldap mount_point=ldap username=myuser password=mypas') }}"

- name: Vault that requires authentication via username and password
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/hola:val auth_method=userpass username=myuser password=psw url=http://vault:8200') }}"

- name: Connect to Vault using TLS
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/hola:value token=c975b780-d1be-8016-866b-01d0f9b688a5 validate_certs=False') }}"

- name: using certificate auth
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/hi:val token=xxxx url=https://vault:8200 validate_certs=True cacert=/cacert/path/ca.pem') }}"

- name: Authenticate with a Vault app role
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/hello:value auth_method=approle role_id=myroleid secret_id=mysecretid') }}"

- name: Return all secrets from a path in a namespace
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/hello token=c975b780-d1be-8016-866b-01d0f9b688a5 namespace=teama/admins') }}"

# When using KV v2 the PATH should include "data" between the secret engine mount and path (e.g. "secret/data/:path")
# see: https://www.vaultproject.io/api/secret/kv/kv-v2.html#read-secret-version
- name: Return latest KV v2 secret from path
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/data/hello token=my_vault_token url=http://myvault_url:8200') }}"

# The following examples show more modern syntax, with parameters specified separately from the term string.

- name: secret= is not required if secret is first
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/hello token=<token> url=http://myvault_url:8200') }}"

- name: options can be specified as parameters rather than put in term string
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/hello', token=my_token_var, url='http://myvault_url:8200') }}"

# return_format (or its alias 'as') can control how secrets are returned to you
- name: return secrets as a dict (default)
  ansible.builtin.set_fact:
    my_secrets: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/manysecrets', token=my_token_var, url='http://myvault_url:8200') }}"
- ansible.builtin.debug:
    msg: "{{ my_secrets['secret_key'] }}"
- ansible.builtin.debug:
    msg: "Secret '{{ item.key }}' has value '{{ item.value }}'"
  loop: "{{ my_secrets | dict2items }}"

- name: return secrets as values only
  ansible.builtin.debug:
    msg: "A secret value: {{ item }}"
  loop: "{{ query('community.hashi_vault.hashi_vault', 'secret/data/manysecrets', token=my_token_var, url='http://vault_url:8200', return_format='values') }}"

- name: return raw secret from API, including metadata
  ansible.builtin.set_fact:
    my_secret: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/hello:value', token=my_token_var, url='http://myvault_url:8200', as='raw') }}"
- ansible.builtin.debug:
    msg: "This is version {{ my_secret['metadata']['version'] }} of hello:value. The secret data is {{ my_secret['data']['data']['value'] }}"

# AWS IAM authentication method
# uses Ansible standard AWS options

- name: authenticate with aws_iam
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/hello:value', auth_method='aws_iam', role_id='myroleid', profile=my_boto_profile) }}"

# JWT auth

- name: Authenticate with a JWT
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/hola:val', auth_method='jwt', role_id='myroleid', jwt='myjwt', url='https://vault:8200') }}"

#GCP auth

- name: Authenticate with GCP
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/hola:val', auth_method='gcp', role_id='myroleid', jwt='myjwt', url='https://vault:8200') }}"

# Disabling Token Validation
# Use this when your token does not have the lookup-self capability. Usually this is applied to all tokens via the default policy.
# However you can choose to create tokens without applying the default policy, or you can modify your default policy not to include it.
# When disabled, your invalid or expired token will be indistinguishable from insufficent permissions.

- name: authenticate without token validation
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/hello:value', token=my_token, token_validate=False) }}"

# "none" auth method does no authentication and does not send a token to the Vault address.
# One example of where this could be used is with a Vault agent where the agent will handle authentication to Vault.
# https://www.vaultproject.io/docs/agent

- name: authenticate with vault agent
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/hello:value', auth_method='none', url='http://127.0.0.1:8100') }}"

# Use a proxy

- name: use a proxy with login/password
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=... token=... url=https://... proxies=https://user:pass@myproxy:8080') }}"

- name: 'use a socks proxy (need some additional dependencies, see: https://requests.readthedocs.io/en/master/user/advanced/#socks )'
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=... token=... url=https://... proxies=socks5://myproxy:1080') }}"

- name: use proxies with a dict (as param)
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', '...', proxies={'http': 'http://myproxy1', 'https': 'http://myproxy2'}) }}"

- name: use proxies with a dict (as param, pre-defined var)
  vars:
    prox:
      http: http://myproxy1
      https: https://myproxy2
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', '...', proxies=prox }}"

- name: use proxies with a dict (as direct ansible var)
  vars:
    ansible_hashi_vault_proxies:
      http: http://myproxy1
      https: https://myproxy2
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', '...' }}"

- name: use proxies with a dict (in the term string, JSON syntax)
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', '... proxies={\\"http\\":\\"http://myproxy1\\",\\"https\\":\\"http://myproxy2\\"}') }}"

- name: use ansible vars to supply some options
  vars:
    ansible_hashi_vault_url: 'https://myvault:8282'
    ansible_hashi_vault_auth_method: token
  set_fact:
    secret1: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/secret1') }}"
    secret2: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/secret2') }}"

- name: use a custom timeout
  debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/secret1', timeout=120) }}"

- name: use a custom timeout and retry on failure 3 times (with collection retry defaults)
  vars:
    ansible_hashi_vault_timeout: 5
    ansible_hashi_vault_retries: 3
  debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/secret1') }}"

- name: retry on failure (with custom retry settings and no warnings)
  vars:
    ansible_hashi_vault_retries:
      total: 6
      backoff_factor: 0.9
      status_forcelist: [500, 502]
      allowed_methods:
        - GET
        - PUT
  debug:
    msg: "{{ lookup('community.hashi_vault.hashi_vault', 'secret/data/secret1', retry_action='warn') }}"
"""

RETURN = """
_raw:
  description:
    - secrets(s) requested
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

        for term in terms:
            opts = kwargs.copy()
            opts.update(self.parse_kev_term(term, first_unqualified='secret', plugin_name='hashi_vault'))
            self.set_options(direct=opts, var_options=variables)
            # TODO: remove process_deprecations() if backported fix is available (see method definition)
            self.process_deprecations()
            self.process_options()

            client_args = self.connection_options.get_hvac_connection_options()
            self.client = self.helper.get_vault_client(**client_args)

            try:
                self.authenticator.authenticate(self.client)
            except (NotImplementedError, HashiVaultValueError) as e:
                raise AnsibleError(e)

            ret.extend(self.get())

        return ret

    def process_options(self):
        '''performs deep validation and value loading for options'''

        # process connection options
        self.connection_options.process_connection_options()

        try:
            self.authenticator.validate()
        except (NotImplementedError, HashiVaultValueError) as e:
            raise AnsibleError(e)

        # secret field splitter
        self.field_ops()

    # begin options processing methods

    def field_ops(self):
        # split secret and field
        secret = self.get_option('secret')

        s_f = secret.rsplit(':', 1)
        self.set_option('secret', s_f[0])
        if len(s_f) >= 2:
            field = s_f[1]
        else:
            field = None

        self._secret_field = field

    def get(self):
        '''gets a secret. should always return a list'''

        field = self._secret_field
        secret = self.get_option('secret')
        return_as = self.get_option('return_format')
        hvac_exceptions = self.helper.get_hvac().exceptions

        try:
            data = self.client.read(secret)
        except hvac_exceptions.Forbidden:
            raise AnsibleError("Forbidden: Permission Denied to secret '%s'." % secret)

        if data is None:
            raise AnsibleError("The secret '%s' doesn't seem to exist." % secret)

        if return_as == 'raw':
            return [data]

        # Check response for KV v2 fields and flatten nested secret data.
        # https://vaultproject.io/api/secret/kv/kv-v2.html#sample-response-1
        try:
            # sentinel field checks
            check_dd = data['data']['data']
            check_md = data['data']['metadata']
            # unwrap nested data
            data = data['data']
        except KeyError:
            pass

        if return_as == 'values':
            return list(data['data'].values())

        # everything after here implements return_as == 'dict'
        if not field:
            return [data['data']]

        if field not in data['data']:
            raise AnsibleError("The secret %s does not contain the field '%s'. for hashi_vault lookup" % (secret, field))

        return [data['data'][field]]
