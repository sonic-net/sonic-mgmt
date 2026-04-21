#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  module: vault_write
  version_added: 2.4.0
  author:
    - Brian Scholer (@briantist)
  short_description: Perform a write operation against HashiCorp Vault
  requirements:
    - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
    - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
  description:
    - Performs a generic write operation against a given path in HashiCorp Vault, returning any output.
  notes:
    - C(vault_write) is a generic module to do operations that do not yet have a dedicated module. Where a specific module exists, that should be used instead.
    - The I(data) option is not treated as secret and may be logged. Use the C(no_log) keyword if I(data) contains sensitive values.
    - This module always reports C(changed) status because it cannot guarantee idempotence.
    - Use C(changed_when) to control that in cases where the operation is known to not change state.
  attributes:
    check_mode:
      support: partial
      details:
        - In check mode, an empty response will be returned and the write will not be performed.
  seealso:
    - ref: community.hashi_vault.vault_write lookup <ansible_collections.community.hashi_vault.vault_write_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_write) lookup plugin.
    - module: community.hashi_vault.vault_read
    - ref: community.hashi_vault.vault_read lookup <ansible_collections.community.hashi_vault.vault_read_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_read) lookup plugin.
  extends_documentation_fragment:
    - community.hashi_vault.attributes
    - community.hashi_vault.attributes.action_group
    - community.hashi_vault.connection
    - community.hashi_vault.auth
    - community.hashi_vault.wrapping
  options:
    path:
      description: Vault path to be written to.
      type: str
      required: True
    data:
      description:
        - A dictionary to be serialized to JSON and then sent as the request body.
        - If the dictionary contains keys named C(path) or C(wrap_ttl), the call will fail with C(hvac<1.2).
      type: dict
      required: false
      default: {}
"""

EXAMPLES = """
- name: Write a value to the cubbyhole via the remote host with userpass auth
  community.hashi_vault.vault_write:
    url: https://vault:8201
    path: cubbyhole/mysecret
    data:
      key1: val1
      key2: val2
    auth_method: userpass
    username: user
    password: '{{ passwd }}'
  register: result

- name: Display the result of the write (this can be empty)
  ansible.builtin.debug:
    msg: "{{ result.data }}"

- name: Write secret to Vault using key value V2 engine
  community.hashi_vault.vault_write:
    path: secret/data/mysecret
    data:
      data:
        key1: val1
        key2: val2

- name: Retrieve an approle role ID from Vault via the remote host
  community.hashi_vault.vault_read:
    url: https://vault:8201
    path: auth/approle/role/role-name/role-id
  register: approle_id

- name: Generate a secret-id for the given approle
  community.hashi_vault.vault_write:
    url: https://vault:8201
    path: auth/approle/role/role-name/secret-id
  register: secret_id

- name: Display the role ID and secret ID
  ansible.builtin.debug:
    msg:
      - "role-id: {{ approle_id.data.data.role_id }}"
      - "secret-id: {{ secret_id.data.data.secret_id }}"
"""

RETURN = """
data:
  description: The raw result of the write against the given path.
  returned: success
  type: dict
"""

import traceback

from ansible.module_utils.common.text.converters import to_text

from ..module_utils._hashi_vault_module import HashiVaultModule
from ..module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        path=dict(type='str', required=True),
        data=dict(type='dict', required=False, default={}),
        wrap_ttl=dict(type='str'),
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    path = module.params.get('path')
    data = module.params.get('data')
    wrap_ttl = module.params.get('wrap_ttl')

    module.connection_options.process_connection_options()
    client_args = module.connection_options.get_hvac_connection_options()
    client = module.helper.get_vault_client(**client_args)
    hvac_exceptions = module.helper.get_hvac().exceptions

    try:
        module.authenticator.validate()
        module.authenticator.authenticate(client)
    except (NotImplementedError, HashiVaultValueError) as e:
        module.fail_json(msg=to_text(e), exception=traceback.format_exc())

    try:
        if module.check_mode:
            response = {}
        else:
            try:
                # TODO: write_data will eventually turn back into write
                # see: https://github.com/hvac/hvac/issues/1034
                response = client.write_data(path=path, wrap_ttl=wrap_ttl, data=data)
            except AttributeError:
                # https://github.com/ansible-collections/community.hashi_vault/issues/389
                if "path" in data or "wrap_ttl" in data:
                    module.fail_json("To use 'path' or 'wrap_ttl' as data keys, use hvac >= 1.2")
                else:
                    response = client.write(path=path, wrap_ttl=wrap_ttl, **data)
    except hvac_exceptions.Forbidden:
        module.fail_json(msg="Forbidden: Permission Denied to path '%s'." % path, exception=traceback.format_exc())
    except hvac_exceptions.InvalidPath:
        module.fail_json(msg="The path '%s' doesn't seem to exist." % path, exception=traceback.format_exc())
    except hvac_exceptions.InternalServerError as e:
        module.fail_json(msg="Internal Server Error: %s" % to_text(e), exception=traceback.format_exc())

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
            module.warn('Vault returned status code %i and an unparsable body.' % response.status_code)
            output = response.content
    else:
        output = response

    module.exit_json(changed=True, data=output)


def main():
    run_module()


if __name__ == '__main__':
    main()
