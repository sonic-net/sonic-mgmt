#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Martin Chmielewski (@M4rt1nCh)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: vault_database_connection_read
version_added: 6.2.0
author:
  - Martin Chmielewski (@M4rt1nCh)
short_description: Returns the configuration settings for a O(connection_name)
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - L(Reads a Database Connection,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/database.html#read-configuration),
    identified by its O(connection_name) from Hashcorp Vault.
notes:
  - This module always reports C(changed) as False as it is a read operation that doesn't modify data.
  - Use C(changed_when) to control that in cases where the operation is known to not change state.
extends_documentation_fragment:
  - community.hashi_vault.attributes
  - community.hashi_vault.attributes.action_group
  - community.hashi_vault.attributes.check_mode_read_only
  - community.hashi_vault.connection
  - community.hashi_vault.auth
  - community.hashi_vault.engine_mount
options:
  connection_name:
    description: The connection name to be read.
    type: str
    required: True
"""

EXAMPLES = r"""
- name: Read a Database Connection with the default mount point
  community.hashi_vault.vault_database_connection_read:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    connection_name: SomeName
  register: result

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"

- name: Read a Database Connection with a custom mount point
  community.hashi_vault.vault_database_connection_read:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: db1
  register: result

- name: Display the result of the operation
  ansible.builtin.debug:
    msg: "{{ result }}"
"""

RETURN = r"""
data: &data
  description: The C(data) field of the RV(raw) result. This can also be accessed via RV(raw.data).
  returned: success
  type: dict
  sample: &data_sample
    allowed_roles: []
    connection_details:
      connection_url: "postgresql://{{username}}:{{password}}@postgres:5432/postgres?sslmode=disable"
      username: "UserName"
    password_policy": ""
    plugin_name": "postgresql-database-plugin"
    plugin_version": ""
    root_credentials_rotate_statements": []
raw:
  description: The raw result of the operation
  returned: success
  type: dict
  contains:
    data: *data
  sample:
    auth: null,
    data: *data_sample
"""

import traceback

from ansible.module_utils.common.text.converters import to_text

from ..module_utils._hashi_vault_module import HashiVaultModule
from ..module_utils._hashi_vault_common import HashiVaultValueError


def run_module():
    argspec = HashiVaultModule.generate_argspec(
        engine_mount_point=dict(type="str", required=False),
        connection_name=dict(type="str", required=True),
    )

    module = HashiVaultModule(argument_spec=argspec, supports_check_mode=True)

    parameters = {}
    engine_mount_point = module.params.get("engine_mount_point", None)
    if engine_mount_point is not None:
        parameters["mount_point"] = engine_mount_point
    parameters["name"] = module.params.get("connection_name")

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
        raw = client.secrets.database.read_connection(**parameters)
    except hvac_exceptions.Forbidden as e:
        module.fail_json(
            msg="Forbidden: Permission Denied to path ['%s']." % engine_mount_point
            or "database",
            exception=traceback.format_exc(),
        )
    except hvac_exceptions.InvalidPath as e:
        module.fail_json(
            msg="Invalid or missing path ['%s/config/%s']."
            % (engine_mount_point or "database", parameters["name"]),
            exception=traceback.format_exc(),
        )

    data = raw["data"]
    module.exit_json(raw=raw, data=data, changed=False)


def main():
    run_module()


if __name__ == "__main__":
    main()
