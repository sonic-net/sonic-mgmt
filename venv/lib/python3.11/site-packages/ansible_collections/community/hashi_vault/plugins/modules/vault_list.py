#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023, Tom Kivlin (@tomkivlin)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
  module: vault_list
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
    - ref: community.hashi_vault.vault_list lookup <ansible_collections.community.hashi_vault.vault_list_lookup>
      description: The official documentation for the C(community.hashi_vault.vault_list) lookup plugin.
  extends_documentation_fragment:
    - community.hashi_vault.attributes
    - community.hashi_vault.attributes.action_group
    - community.hashi_vault.attributes.check_mode_read_only
    - community.hashi_vault.connection
    - community.hashi_vault.auth
  options:
    path:
      description: Vault path to be listed.
      type: str
      required: true
"""

EXAMPLES = """
- name: List kv2 secrets from Vault via the remote host with userpass auth
  community.hashi_vault.vault_list:
    url: https://vault:8201
    path: secret/metadata
    # For kv2, the path needs to follow the pattern 'mount_point/metadata' or 'mount_point/metadata/path' to list all secrets in that path
    auth_method: userpass
    username: user
    password: '{{ passwd }}'
  register: secret

- name: Display the secrets found at the path provided above
  ansible.builtin.debug:
    msg: "{{ secret.data.data['keys'] }}"
    # Note that secret.data.data.keys won't work as 'keys' is a built-in method

- name: List access policies from Vault via the remote host
  community.hashi_vault.vault_list:
    url: https://vault:8201
    path: sys/policies/acl
  register: policies

- name: Display the policy names
  ansible.builtin.debug:
    msg: "{{ policies.data.data['keys'] }}"
    # Note that secret.data.data.keys won't work as 'keys' is a built-in method
"""

RETURN = """
data:
  description: The raw result of the list against the given path.
  returned: success
  type: dict
"""

import traceback

from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule
from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        path=dict(type='str', required=True),
    )

    module = HashiVaultModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    path = module.params.get('path')

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
        data = client.list(path)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(msg="Forbidden: Permission Denied to path '%s'." % path, exception=traceback.format_exc())

    if data is None:
        module.fail_json(msg="The path '%s' doesn't seem to exist." % path)

    module.exit_json(data=data)


def main():
    run_module()


if __name__ == '__main__':
    main()
